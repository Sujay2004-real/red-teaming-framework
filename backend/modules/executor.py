import subprocess
import asyncio
from typing import Dict, Any

class Executor:
    def __init__(self):
        pass

    async def execute_command(self, tool: str, command: str) -> Dict[str, Any]:
        """
        Executes a security tool command asynchronously.
        """
        print(f"Executing: {command}")
        
        try:
            # We use asyncio.create_subprocess_shell
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            stdout, stderr = await process.communicate()
            
            return {
                "tool": tool,
                "command": command,
                "stdout": stdout.decode("utf-8", errors="ignore"),
                "stderr": stderr.decode("utf-8", errors="ignore"),
                "return_code": process.returncode
            }
        except Exception as e:
            return {
                "tool": tool,
                "command": command,
                "stdout": "",
                "stderr": str(e),
                "return_code": -1
            }

executor = Executor()
