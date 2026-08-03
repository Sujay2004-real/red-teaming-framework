import re

class PolicyEngine:
    def __init__(self):
        # We can load this from a config or database later
        self.allowed_tools = ["nmap", "nuclei", "zap-cli"]
        self.blocked_flags = ["-oG", "-oX", "-oN"] # Just examples of preventing arbitrary file writes outside sandbox if needed
        self.dangerous_chars = [";", "|", "&", "`", "$", ">", "<"]

    def validate_target(self, target: str, authorized_scopes: list[str]) -> bool:
        """
        Validates if the target IP/domain is within the authorized scopes.
        Simple string matching for now.
        """
        for scope in authorized_scopes:
            if target == scope or target.endswith("." + scope):
                return True
        return False

    def validate_command(self, command: str) -> bool:
        """
        Validates the generated command string to ensure it's safe.
        """
        parts = command.split()
        if not parts:
            return False

        tool_name = parts[0]
        if tool_name not in self.allowed_tools:
            return False

        for char in self.dangerous_chars:
            if char in command:
                return False

        # Optional: check for blocked flags
        # for flag in self.blocked_flags:
        #     if flag in parts:
        #         return False

        return True

policy_engine = PolicyEngine()
