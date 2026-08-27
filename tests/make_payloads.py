"""Emit JSON analysis request payloads for the acceptance samples."""
import json
import sys
from pathlib import Path

samples = Path(__file__).parent / "samples"
kind = sys.argv[1] if len(sys.argv) > 1 else "safe"

if kind == "safe":
    code = (samples / "safe_sample.js").read_text(encoding="utf-8")
    lang = "javascript"
else:
    code = (samples / "vulnerable_sample.py").read_text(encoding="utf-8")
    lang = "python"

print(json.dumps({"language": lang, "code": code[:6000], "stream": False}))
