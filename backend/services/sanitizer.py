"""Input sanitization for user-supplied analysis options.

The `custom_rules` field is free text that gets embedded in the AI prompt,
so it must never be able to alter the system instructions. Patterns that
resemble prompt-injection attempts are neutralized, and strict size/count
limits are enforced.
"""
import re

MAX_RULES = 20
MAX_RULE_LEN = 200

# Prompt-injection signatures (case-insensitive). Matching rules are
# rejected, not silently mangled — the user can rewrite them.
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|preceding)",
    r"disregard\s+(all\s+|any\s+|the\s+)?(previous|prior|above|instructions)",
    r"forget\s+(all\s+|your\s+|the\s+)?(previous|prior|instructions|prompt)",
    r"system\s*prompt",
    r"you\s+are\s+(now|no\s+longer)",
    r"act\s+as\s+(if|a|an)\b",
    r"pretend\s+(to\s+be|you\s+are)",
    r"new\s+instructions?\s*:",
    r"override\s+(your\s+|the\s+|all\s+)?instructions",
    r"</?\s*(system|assistant|user)\s*>",
    r"\bdeveloper\s+message\b",
    r"\bstop\s+analyzing\b",
    r"respond\s+(only\s+)?with\s*[:\"]?\s*(yes|ok|done)\b",
]

_COMPILED = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]


class RuleRejected(ValueError):
    """A custom rule looks like a prompt-injection attempt."""


def sanitize_custom_rules(rules) -> list:
    """Validate and cap the user-defined rules.

    Returns a clean list of plain search-hint strings.
    Raises RuleRejected when a rule matches an injection signature.
    """
    if rules is None:
        return []
    if not isinstance(rules, (list, tuple)):
        return []

    clean = []
    for r in rules:
        if not isinstance(r, str):
            continue
        r = r.strip()[:MAX_RULE_LEN]
        if not r:
            continue
        for pattern in _COMPILED:
            if pattern.search(r):
                raise RuleRejected(
                    "One of the custom rules was rejected: it looks like an "
                    "attempt to change the AI's instructions. Rewrite it as a "
                    "plain search pattern (e.g. 'admin_mode = true')."
                )
        clean.append(r)
        if len(clean) >= MAX_RULES:
            break
    return clean
