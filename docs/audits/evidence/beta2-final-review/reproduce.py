"""Offline audit probes using freshly built Python code and workflow steps."""
import importlib.util
import json
import subprocess
import sys
from importlib.machinery import ExtensionFileLoader
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[4]
library = ROOT / (sys.argv[1] if len(sys.argv) > 1 else "target/debug/libredact_secret_python.dylib")
spec = importlib.util.spec_from_file_location("_native", library, loader=ExtensionFileLoader("_native", str(library)))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
limits = native.IncrementalLimits(max_input_bytes=32768, max_buffered_bytes=16512,
                                  max_token_bytes=8192, max_multiline_bytes=16384)
observations = {"python": sys.version.split()[0], "invalidAppend": []}
marker = "SYNTHETIC_REVOKED_RETAINED_TEXT"
for invalid in (42, "\ud800"):
    session = native.IncrementalSanitizer(limits)
    assert session.append(marker).text == ""
    error_name = None
    try:
        session.append(invalid)
    except Exception as error:
        error_name = type(error).__name__
    state = session.state
    try:
        reemitted = session.finalize().text == marker
    except Exception:
        reemitted = False
    observations["invalidAppend"].append(dict(error=error_name, stateAfterError=state, reemitted=reemitted))

spec = importlib.util.spec_from_file_location("recovery", ROOT / "scripts/verify-recovery-artifact.py")
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)
inventory = {"artifacts": [{"file": "synthetic.whl", "sha256": "a" * 64},
                            {"file": "synthetic.tar.gz", "sha256": "b" * 64}]}
try:
    recovery.verify_pypi(inventory, {"urls": [{"filename": "synthetic.whl", "digests": {"sha256": "a" * 64}}]})
    observations["matchingPartialPypiRejected"] = False
except ValueError:
    observations["matchingPartialPypiRejected"] = True

# Execute the actual reporter with an offline npm failure stub. Nothing publishes.
workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
step = next(step for step in workflow["jobs"]["publish"]["steps"] if step.get("id") == "state")
script = "npm() { return 1; }\nexport GITHUB_OUTPUT=/dev/stdout\n" + step["run"]
result = subprocess.run(["bash", "-c", script], cwd=ROOT, text=True, capture_output=True, check=True)
state = json.loads(result.stdout.strip().split("registry_state_json=", 1)[1])
observations["npmQueryFailureRecordedAs"] = state["npm:@redact-secret/core"]
print(json.dumps(observations, indent=2))
