"""Fix the malformed single-line logging statement in flow_monitor.py."""
import re

path = "controller/flow_monitor.py"
content = open(path, "r", encoding="utf-8").read()

# The bad line contains literal \n escape sequences on one line
# Find it by looking for the unique prefix
marker = "am_result = safe_emit_verification_alert(self._alert_manager, result, ctx)"

good_replacement = (
    "            am_result = safe_emit_verification_alert(self._alert_manager, result, ctx)\n"
    "            self.logger.info(\n"
    '                "[ALERTING] safe_emit_verification_alert → disposition=%s "\n'
    '                "adapters_ok=%s adapters_failed=%s adapters_skipped=%s reason=%s",\n'
    '                getattr(am_result, "disposition", "None") if am_result is not None else "None",\n'
    '                getattr(am_result, "adapters_ok", "?") if am_result is not None else "?",\n'
    '                getattr(am_result, "adapters_failed", "?") if am_result is not None else "?",\n'
    '                getattr(am_result, "adapters_skipped", "?") if am_result is not None else "?",\n'
    '                getattr(am_result, "reason", "?") if am_result is not None else "?",\n'
    "            )"
)

# Find lines containing the marker and replace them
lines = content.splitlines(keepends=True)
new_lines = []
i = 0
replaced = False
while i < len(lines):
    line = lines[i]
    if not replaced and marker in line and "\\n" in line:
        # This is the bad single-line version
        print(f"Found bad line at line {i+1}: {repr(line[:80])}")
        new_lines.append(good_replacement + "\n")
        replaced = True
    else:
        new_lines.append(line)
    i += 1

if replaced:
    open(path, "w", encoding="utf-8").write("".join(new_lines))
    print("Fixed successfully.")
else:
    print("Bad line NOT found — checking if already fixed...")
    if marker in content:
        print("Marker found but in normal form — already correct.")
    else:
        print("Marker not found at all.")
