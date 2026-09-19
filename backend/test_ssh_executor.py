"""Tests for the Kali VM (tmux-driven SSH) execution engine.

Everything here runs against a scripted fake VM: the paramiko client is
replaced, and the pane's text is produced from what was "typed" plus a
schedule of revealed output lines. The point is to lock down the logic that
is easy to get wrong - exit-marker parsing, pane-transcript trimming, delta
streaming, timeout interruption, and the serialization lock - without
needing a live VM in CI.
"""

import asyncio
import shlex

import pytest

pytest.importorskip('paramiko', reason='SSH execution engine requires paramiko')

import modules.ssh_executor as ssh_executor_module
from modules.ssh_executor import (
    SshExecutor,
    _exit_code,
    _marker_for,
    _recapture,
    _trim_transcript,
    strip_ansi,
)


class FakeKey:
    def asbytes(self):
        return b'host-key-bytes'


class FakeChannel:
    def close(self):
        pass


class FakeStdout:
    def __init__(self, text):
        self._text = text.encode()
        self.channel = FakeChannel()

    def read(self):
        return self._text


class FakeTransport:
    def get_remote_server_key(self):
        return FakeKey()


class FakeVm:
    """A scripted Kali VM: records typed lines, reveals output line by line.

    The pane model mirrors the real one: every typed line is echoed
    immediately (the tty echoes input even while the command runs), and the
    command's output lines appear one per capture-pane poll, with the exit
    marker printed by the shell only after the last output line. "Revealed"
    counts restart with each typed command so a second run interleaves
    correctly.
    """

    def __init__(self, output_lines, exit_code=0, tool_lines=None, tmux_version='tmux 3.4'):
        self.typed = []
        self.output_lines = list(output_lines)
        self.exit_code = exit_code
        self.tool_lines = tool_lines if tool_lines is not None else [
            f'{tool}=/usr/bin/{tool}' for tool in ssh_executor_module.EXPECTED_TOOLS]
        self.tmux_version = tmux_version
        self.captures = 0
        self.captures_at_command = 0
        self.interrupts = 0

    def exec_command(self, command, **kwargs):
        if 'capture-pane' in command:
            self.captures += 1
            return None, FakeStdout(self.pane_text()), None
        if 'send-keys' in command and ' -l ' in command:
            # Mirrors the real _send_line: the text is the single shell-quoted
            # argument after ' -- '.
            self.type_line(shlex.split(command.split(' -- ', 1)[1])[0])
            return None, FakeStdout(''), None
        if 'send-keys' in command and 'Enter' in command:
            return None, FakeStdout(''), None
        if 'send-keys' in command and 'C-c' in command:
            self.interrupts += 1
            return None, FakeStdout(''), None
        if command.startswith('tmux -V'):
            return None, FakeStdout(self.tmux_version), None
        if command.startswith('uname -sr'):
            return None, FakeStdout(
                'Linux 6.12.0-kali\nPRETTY_NAME="Kali GNU/Linux Rolling"\nkali-vm\nroot\n'), None
        if 'command -v' in command:
            return None, FakeStdout('\n'.join(self.tool_lines) + '\n'), None
        return None, FakeStdout(''), None

    def type_line(self, text):
        self.typed.append(text)
        # Everything from the newest non-marker line is a fresh command whose
        # output has not started arriving yet. The combined command+marker
        # line starts with the command, so it resets the reveal counter too.
        if not text.startswith('echo "__RT_EXIT_'):
            self.captures_at_command = self.captures

    def pane_text(self):
        revealed = min(self.captures - self.captures_at_command - 1, len(self.output_lines))
        lines = ['prompt-line'] + ['└─$ ' + typed for typed in self.typed]
        lines.extend(self.output_lines[:max(revealed, 0)])
        # The marker's text rides the combined command line; find it wherever
        # __RT_EXIT_ appears in what was typed.
        markers = []
        for typed in self.typed:
            if '__RT_EXIT_' in typed:
                markers.append(typed.split('__RT_EXIT_')[1].split('__')[0])
        if markers and revealed >= len(self.output_lines):
            token = markers[-1]
            lines.append(f'__RT_EXIT_{token}__:{self.exit_code}')
            lines.append('prompt-line')
        return '\n'.join(lines) + '\n'

    def get_transport(self):
        return FakeTransport()

    def close(self):
        pass


@pytest.fixture
def fast_polling(monkeypatch):
    monkeypatch.setattr(ssh_executor_module, 'POLL_INTERVAL_SECONDS', 0.01)
    monkeypatch.setattr(ssh_executor_module, 'CANCEL_GRACE_SECONDS', 0.05)


def run(coro):
    return asyncio.run(coro)


SETTINGS = {'host': '192.168.56.15', 'port': 22, 'username': 'root', 'password': 'toor'}


def make_executor(monkeypatch, vm):
    executor = SshExecutor()
    monkeypatch.setattr(executor, '_connect', lambda settings: vm)

    def fake_send_line(client, text):
        client.exec_command(
            f'tmux send-keys -t redteam -l -- {shlex.quote(text)} && tmux send-keys -t redteam Enter')

    monkeypatch.setattr(ssh_executor_module, '_send_line', fake_send_line)
    monkeypatch.setattr(ssh_executor_module, '_interrupt',
                        lambda client: client.exec_command('tmux send-keys -t redteam C-c'))
    return executor


# -- pure helpers -----------------------------------------------------------


def test_exit_marker_only_matches_shell_output():
    token = 'abc123'
    assert _exit_code(f'echo "{_marker_for(token)}:$?"\n{_marker_for(token)}:0\n', token) == 0
    assert _exit_code(f'{_marker_for(token)}:2\n', token) == 2
    assert _exit_code('no marker here', token) is None
    # The typed echo shows $? unexpanded, so it must never look like a result.
    assert _exit_code(f'echo "{_marker_for(token)}:$?"', token) is None


def test_trim_transcript_keeps_only_tool_output():
    token = 'tok'
    # Real pane ordering: the tty echoes typed input immediately, so the
    # marker's typed echo appears BEFORE the tool's output; the shell prints
    # its prompt again after the tool exits, then the marker's result line.
    transcript = '\n'.join([
        'prompt-line',
        '└─$ curl -sSI http://192.168.56.10',
        f'└─$ echo "{_marker_for(token)}:$?"',
        'HTTP/1.1 200 OK',
        'Server: nginx',
        'prompt-line',
        f'{_marker_for(token)}:0',
        'prompt-line',
    ])
    trimmed = _trim_transcript(transcript, token, 'curl -sSI http://192.168.56.10')
    assert trimmed.startswith('HTTP/1.1 200 OK\nServer: nginx')
    # The command echo and every marker line are gone; at most the shell's
    # trailing prompt line remains after the tool's output.
    assert 'curl -sSI' not in trimmed
    assert _marker_for(token) not in trimmed
    assert len(trimmed.splitlines()) <= 3


def test_trim_transcript_without_command_echo_still_cuts_at_marker():
    token = 'tok'
    transcript = 'HTTP/1.1 200 OK\n' + f'└─$ echo "{_marker_for(token)}:$?"\n{_marker_for(token)}:0\n'
    assert _trim_transcript(transcript, token, 'never-typed') == 'HTTP/1.1 200 OK'


def test_recapture_streams_deltas_and_resets_on_churn(monkeypatch):
    frames = iter(['a\nb\n', 'a\nb\nc\n', 'x\nc\nd\n'])
    monkeypatch.setattr(ssh_executor_module, '_pane_text', lambda client: next(frames))
    chunks = []
    captured, delta = _recapture(None, 'a\nb\n', chunks)
    assert captured == 'a\nb\n' and delta == '' and chunks == []
    captured, delta = _recapture(None, 'a\nb\n', chunks)
    assert captured == 'a\nb\nc\n' and delta == 'c\n' and chunks == ['c\n']
    # Scrollback dropped the oldest line: the prefix no longer matches, so the
    # whole capture is taken rather than silently losing the seam.
    captured, delta = _recapture(None, 'a\nb\nc\n', chunks)
    assert chunks == ['c\n', 'x\nc\nd\n']
    assert (captured, delta) == ('x\nc\nd\n', 'x\nc\nd\n')


def test_strip_ansi_removes_escapes():
    assert strip_ansi('SSLv3 \x1b[32menabled\x1b[0m') == 'SSLv3 enabled'


# -- full execution ---------------------------------------------------------


def test_execute_command_success_types_streams_and_attests(monkeypatch, fast_polling):
    vm = FakeVm(['HTTP/1.1 200 OK', 'Server: nginx'], exit_code=0)
    executor = make_executor(monkeypatch, vm)
    result = run(executor.execute_command(
        'curl', 'curl -sSI http://192.168.56.10', settings=SETTINGS))
    # One combined line typed into the pane: the command and, in the same
    # line, the exit marker that captures $? the instant the tool finishes.
    assert len(vm.typed) == 1
    assert 'curl -sSI http://192.168.56.10; echo "__RT_EXIT_' in vm.typed[0]
    assert vm.typed[0].endswith('__:$?"')
    assert result['return_code'] == 0
    assert result['stdout'] == 'HTTP/1.1 200 OK\nServer: nginx'
    assert result['stderr'] == ''
    # Attestation identifies the real machine this ran on.
    host = result['execution_host']
    assert host['mode'] == 'kali_vm' and host['host'] == '192.168.56.15'
    assert host['kernel'] == 'Linux 6.12.0-kali'
    assert host['os'] == 'Kali GNU/Linux Rolling'
    assert host['hostname'] == 'kali-vm' and host['user'] == 'root'
    assert host['host_key_fingerprint'].startswith('SHA256:')


def test_execution_streams_to_live_registry(monkeypatch, fast_polling):
    """The live terminal must show VM output while the command runs.

    Deltas are mirrored into the live registry from the monitor thread as
    they are captured - not only once the command finishes.
    """
    vm = FakeVm(['HTTP/1.1 200 OK', 'Server: nginx'], exit_code=0)
    executor = make_executor(monkeypatch, vm)
    streamed = []
    monkeypatch.setattr(ssh_executor_module.live_registry, 'append',
                        lambda execution_id, text: streamed.append((execution_id, text)))
    run(executor.execute_command(
        'curl', 'curl -sSI http://192.168.56.10', execution_id=77, settings=SETTINGS))
    assert streamed, 'no output reached the live registry while the command ran'
    assert all(execution_id == 77 for execution_id, _ in streamed)
    streamed_text = ''.join(text for _, text in streamed)
    assert 'HTTP/1.1 200 OK' in streamed_text and 'Server: nginx' in streamed_text


def test_vm_command_keeps_shell_metacharacters_literal(monkeypatch, fast_polling):
    vm = FakeVm(['HTTP/1.1 200 OK'], exit_code=0)
    executor = make_executor(monkeypatch, vm)
    command = 'curl --data $(id) http://allowed.example/search?a=1&b=2'
    result = run(executor.execute_command('curl', command, settings=SETTINGS))
    typed_command = vm.typed[0].split('; echo ', 1)[0]
    assert "'$(id)'" in typed_command
    assert "'http://allowed.example/search?a=1&b=2'" in typed_command
    assert shlex.split(typed_command)[17:] == shlex.split(command)
    assert result['return_code'] == 0


def test_combined_marker_line_captures_real_exit_code(monkeypatch, fast_polling):
    """Regression: the marker must ride the same input line as the command.

    The live VM showed a separately-queued marker line landing on an idle
    prompt AFTER the tool finished - reporting the prompt's stale $? (130)
    instead of the tool's 0. With one combined line the shell captures the
    tool's own exit status, and only one Enter ever needs to be delivered.
    """
    vm = FakeVm(['HTTP/1.1 200 OK'], exit_code=0)
    executor = make_executor(monkeypatch, vm)
    result = run(executor.execute_command(
        'curl', 'curl -sSI http://192.168.56.10', settings=SETTINGS))
    assert result['return_code'] == 0
    assert len(vm.typed) == 1
    assert 'curl -sSI http://192.168.56.10; echo "__RT_EXIT_' in vm.typed[0]


def test_execute_command_propagates_nonzero_exit(monkeypatch, fast_polling):
    vm = FakeVm(['curl: (7) Failed to connect'], exit_code=7)
    executor = make_executor(monkeypatch, vm)
    result = run(executor.execute_command('curl', 'curl -sSI http://192.168.56.10', settings=SETTINGS))
    assert result['return_code'] == 7
    assert result['stdout'] == 'curl: (7) Failed to connect'


def test_execute_command_timeout_interrupts_pane(monkeypatch, fast_polling):
    vm = FakeVm([f'progress {i}' for i in range(500)], exit_code=0)
    monkeypatch.setattr(ssh_executor_module, 'EXECUTION_TIMEOUT_SECONDS', 0)
    executor = make_executor(monkeypatch, vm)
    result = run(executor.execute_command('nmap', 'nmap -sV 192.168.56.10', settings=SETTINGS))
    assert vm.interrupts >= 1
    assert result['return_code'] == -1
    assert 'timed out' in result['stderr']
    assert result['execution_host'] is not None


def test_execute_command_requires_complete_settings(fast_polling):
    executor = SshExecutor()
    result = run(executor.execute_command(
        'curl', 'curl -I http://192.168.56.10',
        settings={'host': '', 'port': 22, 'username': '', 'password': ''}))
    assert result['return_code'] == -1
    assert 'not configured' in result['stderr']
    assert result['execution_host'] is None


def test_execute_command_without_tmux_reports_install_hint(monkeypatch, fast_polling):
    vm = FakeVm(['x'], tmux_version='bash: tmux: command not found')
    monkeypatch.setattr(ssh_executor_module, '_ensure_session', lambda client: False)
    executor = make_executor(monkeypatch, vm)
    result = run(executor.execute_command('curl', 'curl -I http://192.168.56.10', settings=SETTINGS))
    assert result['return_code'] == -1
    assert 'apt install -y tmux' in result['stderr']


def test_proxy_environment_is_private_and_removed(monkeypatch, fast_polling):
    from contextlib import contextmanager
    vm = FakeVm(['HTTP/1.1 200 OK'], exit_code=0)
    events = []
    class Files:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def open(self, path, mode):
            events.append(('open', path, mode))
            return self
        def chmod(self, path, mode): events.append(('chmod', path, mode))
        def write(self, text): events.append(('write', text))
        def remove(self, path): events.append(('remove', path))
    vm.open_sftp = Files
    executor = make_executor(monkeypatch, vm)
    result = run(executor.execute_command('curl', 'curl -I http://192.168.56.10',
        proxy_env={'HTTP_PROXY': 'http://user:secret@proxy:8080'}, settings=SETTINGS))
    assert result['return_code'] == 0
    assert len(vm.typed) == 1 and 'secret' not in vm.typed[0]
    assert vm.typed[0].startswith('env -u HTTP_PROXY')
    assert events[1][0] == 'chmod' and events[1][2] == 0o600
    assert 'secret' in events[2][1] and events[-1][0] == 'remove'


def test_pane_usage_is_serialized(monkeypatch, fast_polling):
    """One shared pane means one command at a time.

    Two concurrent executions must not interleave their typed lines; the
    second command may only be typed after the first finished, never between
    the first command and its marker.
    """
    vm = FakeVm(['HTTP/1.1 200 OK'], exit_code=0)
    executor = make_executor(monkeypatch, vm)

    async def both():
        return await asyncio.gather(
            executor.execute_command('curl', 'curl -sSI http://192.168.56.10', settings=SETTINGS),
            executor.execute_command('dig', 'dig +short 192.168.56.10', settings=SETTINGS),
        )

    first, second = run(both())
    assert first['return_code'] == 0 and second['return_code'] == 0
    typed = [line for line in vm.typed if not line.startswith('echo ')
             and not line.split('; echo ')[0].startswith('echo ')]
    assert [shlex.join(shlex.split(line.split('; echo ')[0])[17:]) for line in typed] == [
        'curl -sSI http://192.168.56.10', 'dig +short 192.168.56.10']


# -- connection test --------------------------------------------------------


def test_test_connection_attests_and_inventories(monkeypatch):
    vm = FakeVm([])
    executor = make_executor(monkeypatch, vm)
    result = executor.test_connection(SETTINGS)
    assert result['tmux_ok'] is True
    assert result['os'] == 'Kali GNU/Linux Rolling'
    assert result['host_key_fingerprint'].startswith('SHA256:')
    assert result['missing'] == []
    assert set(result['tools']) == set(ssh_executor_module.EXPECTED_TOOLS)


def test_test_connection_reports_missing_tools(monkeypatch):
    vm = FakeVm([])
    vm.tool_lines = [f'{t}=/usr/bin/{t}' for t in ('nmap', 'traceroute', 'dig', 'nslookup', 'curl', 'whatweb', 'sslscan')] + ['nuclei=MISSING']
    executor = make_executor(monkeypatch, vm)
    result = executor.test_connection(SETTINGS)
    assert result['missing'] == ['nuclei']
    assert 'nuclei' in result['install_hint']


def test_test_connection_without_tmux(monkeypatch):
    vm = FakeVm([], tmux_version='')
    monkeypatch.setattr(ssh_executor_module, '_ensure_session', lambda client: False)
    executor = make_executor(monkeypatch, vm)
    result = executor.test_connection(SETTINGS)
    assert result['tmux_ok'] is False
    assert 'tmux' in result['install_hint']
