"""Same-process isolation probe for the Python wheel (issue #1221).

    cd bindings/python && maturin build --release --locked -o <dir>/wheels
    python3 -m venv <dir>/venv && <dir>/venv/bin/pip install <dir>/wheels/*.whl
    <dir>/venv/bin/python -I docs/audits/evidence/1221/probe-python.py

The wheel keeps the PII selection in one process-wide static, so A (off),
B (pii:global) and C (network-address only) cannot coexist in one process,
whether on threads or in sub-interpreters. Separate processes can. Every value
is synthetic and assembled at run time.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading

EMAIL = "email: owner.synthetic@mail-synthetic.org"
IP = "client_ip = 192.168.1.7"
SELECTION = {"A": [], "B": ["pii:global"], "C": ["pii:family:global:network-address"]}
CHILD = """
import json, sys
import redact_secret as r
role_selection = json.loads(sys.argv[1])
r.initialize(pii=role_selection)
print(json.dumps({"activation": r.pii_activation(),
  "email": len(r.scan("%s")), "ip": len(r.scan("%s"))}))
""" % (EMAIL, IP)


def record(name: str, value: object) -> None:
    print(f"{name}: {json.dumps(value)}")


def code(error: BaseException) -> str:
    return type(error).__name__


def main() -> None:
    import redact_secret as r

    record("wheel.version", r.__version__)
    record("status.beforeInitialize", repr(r.status()))

    # 1. Same process: the first selection wins; every differing one conflicts.
    r.initialize(pii=SELECTION["B"])
    record("status.afterB", repr(r.status()))
    outcomes = {}
    for role in ("A", "C"):
        try:
            r.initialize(pii=SELECTION[role])
            outcomes[role] = "ok"
        except Exception as error:  # noqa: BLE001 - recording the class is the point
            outcomes[role] = code(error)
    try:
        r.initialize(pii=["pii"])  # equivalent spelling of pii:global
        outcomes["B-equivalent"] = "ok"
    except Exception as error:  # noqa: BLE001
        outcomes["B-equivalent"] = code(error)
    record("sameProcess.initializeAfterB", outcomes)
    assert outcomes["A"] == "PiiActivationConflictError"
    assert outcomes["C"] == "PiiActivationConflictError"
    assert outcomes["B-equivalent"] == "ok"

    # 2. Threads share the one static: a second thread cannot pick another selection.
    thread_result: dict[str, object] = {}

    def worker() -> None:
        try:
            r.initialize(pii=SELECTION["C"])
            thread_result["c"] = "ok"
        except Exception as error:  # noqa: BLE001
            thread_result["c"] = code(error)
        thread_result["email"] = len(r.scan(EMAIL))

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()
    record("threads.cOnSecondThread", thread_result)
    assert thread_result["c"] == "PiiActivationConflictError"
    assert thread_result["email"] == 1  # the process-wide B selection applies

    # 3. Sub-interpreters (3.14+): record whether the extension imports at all.
    try:
        from concurrent import interpreters

        interp = interpreters.create()
        try:
            interp.exec("import redact_secret")
            record("subinterpreter.import", "ok")
        except Exception as error:  # noqa: BLE001
            record("subinterpreter.import", code(error))
        interp.close()
    except ImportError:
        record("subinterpreter.import", "concurrent.interpreters unavailable")

    # 4. Separate processes are independent owners; order does not matter.
    signatures = set()
    for order in (("A", "B", "C"), ("C", "B", "A"), ("B", "A", "C")):
        sig = {}
        for role in order:
            done = subprocess.run(
                [sys.executable, "-I", "-c", CHILD, json.dumps(SELECTION[role])],
                capture_output=True, text=True, check=True,
            )
            parsed = json.loads(done.stdout)
            sig[role] = [parsed["email"], parsed["ip"]]
        signatures.add(json.dumps(sig, sort_keys=True))
    record("processes.signatures", sorted(signatures))
    assert len(signatures) == 1
    only = json.loads(next(iter(signatures)))
    assert only == {"A": [0, 0], "B": [1, 1], "C": [0, 1]}
    print("PASS python probe")


main()
