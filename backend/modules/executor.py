import asyncio
import os
import shlex
import signal
import time

MAX_OUTPUT_CHARS = 200_000
# Stop accumulating well before memory pressure, but keep draining the pipes so
# a chatty scanner never blocks on a full buffer and stalls until the timeout.
MAX_OUTPUT_BYTES = MAX_OUTPUT_CHARS * 4
EXECUTION_TIMEOUT_SECONDS = 300
READ_CHUNK_BYTES = 65_536
# Scanners inherit only what they need to run. Passing the whole parent
# environment would hand GEMINI_API_KEY and DATABASE_URL to every subprocess.
INHERITED_ENV_KEYS = (
    'PATH', 'HOME', 'USERPROFILE', 'LANG', 'LC_ALL', 'TERM',
    'TMPDIR', 'TEMP', 'TMP', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT',
)


async def _drain(stream, chunks):
    """Read a pipe to EOF, retaining at most MAX_OUTPUT_BYTES of it."""
    retained = 0
    while True:
        chunk = await stream.read(READ_CHUNK_BYTES)
        if not chunk:
            return
        if retained < MAX_OUTPUT_BYTES:
            chunks.append(chunk[:MAX_OUTPUT_BYTES - retained])
            retained += len(chunk)


def _truncate(chunks, label):
    text = b''.join(chunks).decode(errors='ignore')
    if len(text) > MAX_OUTPUT_CHARS:
        return text[:MAX_OUTPUT_CHARS] + f'\n[{label} truncated]'
    return text


class Executor:
    def build_environment(self, proxy_env=None):
        env = {key: os.environ[key] for key in INHERITED_ENV_KEYS if key in os.environ}
        env.update(proxy_env or {})
        return env

    def _terminate(self, process):
        """Kill the whole process group; nmap and nuclei both spawn children."""
        try:
            if os.name == 'posix':
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            else:
                process.kill()
        except (ProcessLookupError, PermissionError, OSError):
            pass

    async def execute_command(self, tool, command, proxy_env=None):
        started = time.perf_counter()
        elapsed = lambda: round((time.perf_counter() - started) * 1000)
        stdout_chunks, stderr_chunks = [], []
        process = None
        try:
            tokens = shlex.split(command, posix=True)
            if not tokens:
                raise ValueError('Command is empty')
            process = await asyncio.create_subprocess_exec(
                *tokens,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self.build_environment(proxy_env),
                **({'start_new_session': True} if os.name == 'posix' else {}),
            )
            readers = asyncio.gather(
                _drain(process.stdout, stdout_chunks),
                _drain(process.stderr, stderr_chunks),
                process.wait(),
            )
            try:
                await asyncio.wait_for(readers, timeout=EXECUTION_TIMEOUT_SECONDS)
                return_code = process.returncode
                timed_out = False
            except asyncio.TimeoutError:
                self._terminate(process)
                await process.wait()
                return_code = -1
                timed_out = True

            stdout = _truncate(stdout_chunks, 'stdout')
            stderr = _truncate(stderr_chunks, 'stderr')
            if timed_out:
                notice = f'Execution timed out after {EXECUTION_TIMEOUT_SECONDS} seconds; output below is partial.'
                stderr = f'{notice}\n{stderr}'.strip()
            return {'tool': tool, 'command': command, 'stdout': stdout, 'stderr': stderr, 'return_code': return_code, 'duration_ms': elapsed()}
        except Exception as exc:
            return {'tool': tool, 'command': command, 'stdout': _truncate(stdout_chunks, 'stdout'), 'stderr': str(exc), 'return_code': -1, 'duration_ms': elapsed()}
        finally:
            # A client disconnect cancels this coroutine, and CancelledError is a
            # BaseException that no except clause here catches, so the scanner
            # used to keep running - and keep hammering the target - long after
            # nobody was left to read its output. The same applied to any
            # unexpected error raised while the readers were still attached.
            if process is not None and process.returncode is None:
                self._terminate(process)


executor = Executor()
