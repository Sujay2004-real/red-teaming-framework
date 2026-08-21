import asyncio
import shlex
import time

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
            return {'tool': tool, 'command': command, 'stdout': stdout.decode(errors='ignore'), 'stderr': stderr.decode(errors='ignore'), 'return_code': process.returncode, 'duration_ms': round((time.perf_counter()-started)*1000)}
        except Exception as exc:
            return {'tool': tool, 'command': command, 'stdout': '', 'stderr': str(exc), 'return_code': -1, 'duration_ms': round((time.perf_counter()-started)*1000)}

executor = Executor()
