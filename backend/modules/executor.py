import asyncio
import shlex
import time

MAX_OUTPUT_CHARS = 200_000

class Executor:
    async def execute_command(self, tool, command, proxy_env=None):
        started = time.perf_counter()
        try:
            tokens = shlex.split(command, posix=True)
            env = None
            if proxy_env:
                import os
                env = {**os.environ, **proxy_env}
            process = await asyncio.create_subprocess_exec(*tokens, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
            except asyncio.TimeoutError:
                process.kill()
                await process.communicate()
                return {'tool': tool, 'command': command, 'stdout': '', 'stderr': 'Execution timed out after 300 seconds.', 'return_code': -1, 'duration_ms': 300000}
            decoded_stdout = stdout.decode(errors='ignore')
            decoded_stderr = stderr.decode(errors='ignore')
            if len(decoded_stdout) > MAX_OUTPUT_CHARS:
                decoded_stdout = decoded_stdout[:MAX_OUTPUT_CHARS] + '\n[stdout truncated]'
            if len(decoded_stderr) > MAX_OUTPUT_CHARS:
                decoded_stderr = decoded_stderr[:MAX_OUTPUT_CHARS] + '\n[stderr truncated]'
            return {'tool': tool, 'command': command, 'stdout': decoded_stdout, 'stderr': decoded_stderr, 'return_code': process.returncode, 'duration_ms': round((time.perf_counter()-started)*1000)}
        except Exception as exc:
            return {'tool': tool, 'command': command, 'stdout': '', 'stderr': str(exc), 'return_code': -1, 'duration_ms': round((time.perf_counter()-started)*1000)}

executor = Executor()
