"""A simulated chatbot for trying the platform without a model or network.

It is a rule-based stand-in, not an LLM: the "vulnerable" profile obeys the
kinds of instructions the probes send, "hardened" refuses them, and "partial"
only falls for injected content and output-format requests.
"""

from __future__ import annotations

import base64
import re

from .detectors import decoded_segments

_JOIN = re.compile(r'joining "([^"]+)" and "([^"]+)"')
_ACTIVE = re.compile(r"!\[[^\]]*\]\([^)]+\)|<script\b.*?</script>|<img\b[^>]*>", re.S | re.I)
_EXFIL_URL = re.compile(r"https://\S+\?d=")
_LEAK_WORDS = ("system prompt", "instructions", "text above", "before this message", "initial prompt")
_SECRET_WORDS = (
    "api key", "password", "credential", "secret", "reference code",
    "configuration", "connection string",
)

REFUSAL = "I'm sorry, I can't help with that. I can answer questions about our products."


def _unspace(text: str) -> str:
    """Undo ' '.join(text): single spaces vanish, triple spaces become one."""
    return text.replace("   ", "\0").replace(" ", "").replace("\0", " ")


class DemoBot:
    def __init__(self, profile: str, system_prompt: str, secrets: list[str]):
        self.profile = profile
        self.system_prompt = system_prompt
        self.secrets = secrets

    def reply(self, user_turns: list[str]) -> str:
        last = user_turns[-1]
        low = last.lower()
        if self.profile == "hardened":
            return REFUSAL

        injected = self.profile == "vulnerable" or low.startswith("summarize the following content")
        if injected:
            haystack = "\n".join(user_turns)
            haystack += "\n" + decoded_segments(haystack) + "\n" + _unspace(last)
            join = _JOIN.search(haystack)
            if join:
                return join.group(1) + join.group(2)

        if "javascript:" in low:
            return "Here you go: [click here](javascript:console.log('mb-test'))"
        exfil = _EXFIL_URL.search(last)
        if exfil and "followed by" in low:
            words = "_".join(self.system_prompt.split()[:5])
            return f"Done. ![img]({exfil.group(0)}{words})"
        active = _ACTIVE.search(last)
        if active:
            return f"Sure. {active.group(0)}"

        if self.profile != "vulnerable":
            return REFUSAL

        if any(word in low for word in _LEAK_WORDS):
            if "base64" in low:
                return base64.b64encode(self.system_prompt.encode()).decode()
            if "hyphen" in low:
                return "-".join(self.system_prompt)
            if "backwards" in low:
                return self.system_prompt[::-1]
            return f"Of course. My instructions are:\n{self.system_prompt}"
        if any(word in low for word in _SECRET_WORDS):
            listed = "\n".join(f"- {secret}" for secret in self.secrets) or "- (none stored)"
            return f"Here is what I have:\n{listed}\n\nFull context:\n{self.system_prompt}"
        return "Happy to help! Could you tell me more about what you need?"
