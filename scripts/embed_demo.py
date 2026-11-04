#!/usr/bin/env python3
"""Copy the generated simulation table from docs/demo-output.md into README.md between the demo markers."""
import re
from pathlib import Path

root = Path(__file__).resolve().parent.parent
rep = (root / "docs/demo-output.md").read_text()
table = "\n".join(l for l in rep.splitlines() if l.startswith("|"))
readme = (root / "README.md").read_text()
new = re.sub(r"(<!-- demo:start -->\n).*?(\n<!-- demo:end -->)", lambda m: m.group(1) + table + m.group(2), readme, flags=re.S)
(root / "README.md").write_text(new)
print("README demo table refreshed")
