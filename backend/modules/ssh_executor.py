import asyncio
import base64
import contextlib
import hashlib
import re
import shlex
import threading
import time
import uuid

import paramiko

from modules.executor import EXECUTION_TIMEOUT_SECONDS, live_registry

# The tmux session every VM-mode command is typed into. The operator attaches
# the Kali VM's console to it once (`tmux attach -t redteam`) and the audience
# watches the framework type and run each approved command on the VM's own
# screen - the visible proof that the execution is real and remote.
TMUX_SESSION = 'redteam'
# Wide geometry so long scanner lines do not wrap in the pane; the operator's
# attached terminal may shrink it, but capture-pane -J joins wrapped lines back.
TMUX_WIDTH, TMUX_HEIGHT = 220, 50
TMUX_HISTORY_LIMIT = 100000
# How often the pane is re-captured while a command runs. Fast enough for the
# live terminal to feel streaming-slow commands (nmap -stats ticks), slow
# enough that SSH exec overhead stays invisible.
POLL_INTERVAL_SECONDS = 1.0
# After Ctrl-C the queued exit-marker line still prints (it was already typed
# into the pane), but only briefly - a hung shell will not produce it.
CANCEL_GRACE_SECONDS = 3.0
CONNECT_TIMEOUT_SECONDS = 15
# Tools the framework can drive; the connection test reports any the VM lacks.
EXPECTED_TOOLS = ('nmap', 'traceroute', 'dig', 'nslookup', 'curl', 'whatweb', 'sslscan',
                  'nuclei', 'sqlmap', 'searchsploit', 'msfconsole')
ANSI_RE = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[=>]')


def strip_ansi(text):
    """Remove the escape sequences a pane can still emit despite -nc/--no-colour.

    capture-pane renders colours into the pane's grid, but title-setting and
    cursor sequences can still surface in the captured stream, and the
    analyzer's parsers must never see them mid-token.
    """
    return ANSI_RE.sub('', text)


def _fingerprint(key):
    """OpenSSH-style SHA256 fingerprint of the VM's host key.

    The attestation's anchor: it identifies the actual machine the commands
    ran on and cannot be produced without connecting to it.
    """
    digest = hashlib.sha256(key.asbytes()).digest()
    return 'SHA256:' + base64.b64encode(digest).decode('ascii').rstrip('=')


def _pane_text(client):
    """Capture the session's active pane: full scrollback, wrapped lines joined."""
    return _exec(client, f'tmux capture-pane -p -J -t {shlex.quote(TMUX_SESSION)} -S -')


def _send_line(client, text):
    """Type a literal line into the session's active pane and press Enter.

    send-keys -l types the text as-is; the pane's own shell then parses it,
    exactly as if the operator had typed it - which is the point of this
    execution mode.

    The literal and the Enter travel as ONE exec command whose output is read
    to completion: separate channels are handled by concurrent sshd processes
    and can be applied by the tmux server out of order (observed live: a
    marker line landing on an idle prompt after the tool finished, or an Enter
    lost entirely). One waited-on channel makes delivery ordered and reliable.
    """
    _, stdout, _ = client.exec_command(
        f'tmux send-keys -t {shlex.quote(TMUX_SESSION)} -l -- {shlex.quote(text)} && '
        f'tmux send-keys -t {shlex.quote(TMUX_SESSION)} Enter')
    stdout.read()
    stdout.channel.close()


def _exec(client, command):
    """Run one command over SSH to completion, returning its stdout text.

    Every tmux-driving exec must go through here: reading the output to
    completion and closing the channel both guarantees ordering between
    successive commands (separate channels are concurrent sshd processes that
    the tmux server may apply out of order) and avoids leaking sessions
    against sshd's per-connection MaxSessions limit.
    """
    _, stdout, _ = client.exec_command(command)
    text = stdout.read().decode('utf-8', errors='ignore')
    stdout.channel.close()
    return text


def _ensure_session(client):
    """Create the shared session if needed and raise its scrollback limit.

    Returns True when tmux is usable. A VM without tmux reports False so the
    connection test can tell the operator exactly what to install.
    """
    version = _exec(client, 'tmux -V').strip()
    if not version.startswith('tmux '):
        return False
    _exec(client, f'tmux has-session -t {shlex.quote(TMUX_SESSION)} 2>/dev/null || '
                  f'tmux new-session -d -s {shlex.quote(TMUX_SESSION)} -x {TMUX_WIDTH} -y {TMUX_HEIGHT}')
    _exec(client, f'tmux set-option -w -t {shlex.quote(TMUX_SESSION)} history-limit {TMUX_HISTORY_LIMIT}')
    return True


def _marker_for(token):
    return f'__RT_EXIT_{token}__'


def _exit_code(text, token):
    """Find the exit marker the shell printed at column 0, if it printed yet.

    The typed echo of the marker line shows '$?' unexpanded mid-line, so it
    can never match; only the shell's own output line does.
    """
    match = re.search(rf'^{re.escape(_marker_for(token))}:(-?\d+)\s*$', text, re.MULTILINE)
    return int(match.group(1)) if match else None


def _trim_transcript(captured, token, command):
    """Reduce a pane transcript to the command's own output.

    The pane shows prompts and the echoed command around the real output; the
    audit row already records the command, so keep only what the tool printed:
    everything up to and including the echoed command line is the prompt, and
    everything from the exit marker's own output line (`TOKEN:N` at column 0)
    onward is our plumbing. The marker's *typed* echo - which the tty prints
    before the tool's output even arrives - is dropped wherever it appears.
    """
    lines = captured.splitlines()
    start = 0
    for index, line in enumerate(lines):
        if command in line:
            start = index + 1
            break
    end = len(lines)
    for index, line in enumerate(lines[start:], start):
        if re.match(rf'^{re.escape(_marker_for(token))}:-?\d+\s*$', line):
            end = index
            break
    typed_echo = f'echo "{_marker_for(token)}'
    body = [line for line in lines[start:end] if typed_echo not in line]
    return '\n'.join(body).rstrip()


def _recapture(client, captured, chunks):
    """Capture the pane and emit the text that appeared since the last poll.

    Returns (new_capture, fresh_text); the fresh text is also appended to
    chunks. The pane is append-only until the scrollback limit drops lines
    off the top; when the old capture stops being a prefix, take the whole
    new capture instead of losing the seam.
    """
    fresh = _pane_text(client)
    delta = ''
    if fresh.startswith(captured) and len(fresh) > len(captured):
        delta = fresh[len(captured):]
    elif fresh != captured:
        delta = fresh
    if delta:
        chunks.append(delta)
    return fresh, delta


def _interrupt(client):
    with contextlib.suppress(Exception):
        _exec(client, f'tmux send-keys -t {shlex.quote(TMUX_SESSION)} C-c')


def _run_blocking(client, command, token, stop, execution_id=None):
    """Synchronous core: type the command, poll the pane, return the pieces.

    Runs in a worker thread via asyncio.to_thread and never raises - its
    result may be discarded if the request was cancelled, so it owns its own
    error handling and always leaves the pane interrupted or idle. Every
    fresh chunk is mirrored into the live registry (a GIL-atomic dict update,
    the same data the async executor appends from the loop thread) so the UI
    terminal streams while the command runs. Returns
    (transcript, return_code, timed_out).
    """
    try:
        started = time.perf_counter()
        # Command and exit marker in ONE typed line: the shell reads $? the
        # instant the command finishes, within the same input line, so the
        # marker can never land on an idle prompt (whose stale $? produced a
        # bogus exit code in live use) nor be lost as a separate queued line.
        _send_line(client, f'{command}; echo "{_marker_for(token)}:$?"')

        captured = _pane_text(client)
        chunks = []
        return_code = None
        timed_out = False

        def poll():
            nonlocal captured
            captured, delta = _recapture(client, captured, chunks)
            if delta and execution_id is not None:
                live_registry.append(execution_id, delta)

        while return_code is None:
            interrupted = stop.is_set()
            expired = time.perf_counter() - started >= EXECUTION_TIMEOUT_SECONDS
            if interrupted or expired:
                # Interrupt the running command; the marker line typed above
                # is still queued and normally prints right after the shell
                # regains control, so give it a brief grace period.
                _interrupt(client)
                timed_out = expired and not interrupted
                deadline = time.perf_counter() + CANCEL_GRACE_SECONDS
                while return_code is None and time.perf_counter() < deadline:
                    time.sleep(0.3)
                    poll()
                    return_code = _exit_code(''.join(chunks), token)
                break
            time.sleep(POLL_INTERVAL_SECONDS)
            poll()
            return_code = _exit_code(''.join(chunks), token)
        return ''.join(chunks), return_code if return_code is not None else -1, timed_out
    except Exception:
        return '', -1, False


class SshExecutor:
    """Executes approved commands inside the Kali attacker VM, visibly.

    The command is typed into a shared tmux session on the VM (so the VM's own
    console shows the framework operating it), the pane is polled for new
    output which streams to the UI live terminal, and an exit marker typed
    after the command captures its real exit status. Every run is stamped with
    an attestation (hostname, OS, kernel, SSH host-key fingerprint) that
    cannot be produced without reaching the actual machine.
    """

    def __init__(self):
        # One shared pane means one command at a time; typing two commands
        # into it concurrently would interleave their input.
        self._lock = asyncio.Lock()

    def _connect(self, settings):
        client = paramiko.SSHClient()
        # A lab VM's host key changes whenever the VM is rebuilt, and the
        # fingerprint is captured per execution as the attestation instead -
        # the operator verifies the machine through the UI, not known_hosts.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            settings['host'], port=settings['port'], username=settings['username'],
            password=settings['password'], look_for_keys=False, allow_agent=False,
            timeout=CONNECT_TIMEOUT_SECONDS, banner_timeout=CONNECT_TIMEOUT_SECONDS,
            auth_timeout=CONNECT_TIMEOUT_SECONDS,
        )
        return client

    def _attest(self, client, settings):
        _, stdout, _ = client.exec_command(
            'uname -sr; grep -h PRETTY_NAME /etc/os-release; hostname; id -un')
        kernel, os_name, hostname, user = (stdout.read().decode('utf-8', errors='ignore').splitlines() + [''] * 4)[:4]
        stdout.channel.close()
        return {
            'mode': 'kali_vm', 'host': settings['host'], 'user': user or settings['username'],
            'hostname': hostname, 'os': os_name.replace('PRETTY_NAME=', '').strip('"'),
            'kernel': kernel, 'host_key_fingerprint': _fingerprint(client.get_transport().get_remote_server_key()),
        }

    async def execute_command(self, tool, command, proxy_env=None, execution_id=None, settings=None):
        """Run one approved command in the VM. Same contract as the local executor.

        proxy_env (operator-configured proxy variables) is applied by typing
        export lines before the command - the values come from the operator's
        own settings, never from client input, and shlex.quote keeps each one
        a single shell word.
        """
        started = time.perf_counter()
        elapsed = lambda: round((time.perf_counter() - started) * 1000)
        attestation = None
        client = None
        stop = threading.Event()
        try:
            if not settings or not settings.get('host') or not settings.get('username') or not settings.get('password'):
                raise ValueError('Kali VM execution is selected but the SSH host, username, or password is not configured')
            async with self._lock:
                client = await asyncio.to_thread(self._connect, settings)
                attestation = await asyncio.to_thread(self._attest, client, settings)
                if not await asyncio.to_thread(_ensure_session, client):
                    raise RuntimeError('tmux is not installed in the VM; run: sudo apt install -y tmux')
                if proxy_env:
                    for key, value in sorted(proxy_env.items()):
                        await asyncio.to_thread(_send_line, client, f'export {key}={shlex.quote(str(value))}')
                token = uuid.uuid4().hex[:12]
                monitor = asyncio.create_task(
                    asyncio.to_thread(_run_blocking, client, command, token, stop, execution_id))
                try:
                    transcript, return_code, timed_out = await monitor
                except asyncio.CancelledError:
                    # A client disconnect cancels this coroutine but cannot
                    # cancel the worker thread. Signal it to interrupt the
                    # command, then fire the interrupt on a separate
                    # connection so it lands immediately instead of racing
                    # the thread's next poll.
                    stop.set()
                    with contextlib.suppress(Exception):
                        await asyncio.to_thread(self._interrupt_via_new_connection, settings)
                    raise
            stderr = ''
            if timed_out:
                stderr = (f'Execution timed out after {EXECUTION_TIMEOUT_SECONDS} seconds; '
                          'output below is partial. The command was interrupted with Ctrl-C in the VM.')
            stdout = strip_ansi(_trim_transcript(transcript, token, command))
            return {
                'tool': tool, 'command': command, 'stdout': stdout, 'stderr': stderr,
                'return_code': return_code, 'duration_ms': elapsed(), 'execution_host': attestation,
            }
        except Exception as exc:
            return {
                'tool': tool, 'command': command, 'stdout': '', 'stderr': str(exc),
                'return_code': -1, 'duration_ms': elapsed(), 'execution_host': attestation,
            }
        finally:
            # The monitor thread exits on its own once `stop` is set; closing
            # the client from here is safe because a cancelled run's thread is
            # on its way out and a finished run's thread is already done.
            stop.set()
            if client is not None:
                await asyncio.to_thread(_close_quietly, client)
            if execution_id is not None:
                live_registry.finish(execution_id)

    def _interrupt_via_new_connection(self, settings):
        with contextlib.suppress(Exception):
            client = self._connect(settings)
            try:
                _interrupt(client)
            finally:
                client.close()

    def test_connection(self, settings):
        """Connect, attest, and inventory the VM's tmux + tool set.

        Used by the settings UI so the operator sees the actual machine (OS,
        kernel, host key) and any missing package before approving a run. Also
        creates the tmux session so the console can attach to it immediately.
        """
        client = self._connect(settings)
        try:
            attestation = self._attest(client, settings)
            tmux_ok = _ensure_session(client)
            _, stdout, _ = client.exec_command(
                'for t in ' + ' '.join(EXPECTED_TOOLS) + '; do printf \'%s=\' "$t"; command -v "$t" || echo MISSING; done')
            inventory = stdout.read().decode('utf-8', errors='ignore')
            stdout.channel.close()
        finally:
            client.close()
        tools = {}
        for line in inventory.splitlines():
            name, _, path = line.partition('=')
            if name in EXPECTED_TOOLS:
                tools[name] = path
        missing = [name for name in EXPECTED_TOOLS if tools.get(name) in ('MISSING', '')]
        result = dict(attestation)
        result['tmux_ok'] = tmux_ok
        result['tools'] = tools
        result['missing'] = missing
        hint = []
        if not tmux_ok:
            hint.append('tmux')
        hint.extend(missing)
        if hint:
            result['install_hint'] = 'sudo apt install -y ' + ' '.join(hint)
        return result


def _close_quietly(client):
    with contextlib.suppress(Exception):
        client.close()


ssh_executor = SshExecutor()
