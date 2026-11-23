"""Synthetic wire bytes only: successful paths always use the actual S0 reader.

No S1 synthetic.make_frame or signature-only synthetic PNG is used here.
"""

import importlib.util
import json
from pathlib import Path


# Explicit file-module import: unittest discovery also works without tests/__init__.py.
_spec = importlib.util.spec_from_file_location(
    "siteproof_int01_wire_fixtures", Path(__file__).parents[1] / "isolation/wire_fixtures.py")
wire = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wire)


def record(check, **observation):
    return json.dumps({"schema_version": "siteproof.record.v0.1",
                       "record_type": check, "observation": observation},
                      separators=(",", ":")).encode("utf-8")


def http(status=200):
    return record("HTTP", state="OBSERVED", status_code=status, reason_code=f"HTTP_{status}")


def load(state="SUCCEEDED", reason="LOAD_OK"):
    return record("LOAD", state=state, reason_code=reason)


def capture(baseline=None, state="SUCCEEDED", reason=None, comparison=None):
    comparison = comparison or ("NOT_EVALUATED" if baseline else "BASELINE_PENDING")
    reason = reason or ("COMPARISON_NOT_RUN" if baseline else "BASELINE_NOT_SET")
    return record("CAPTURE", capture_state=state, comparison_state=comparison, reason_code=reason)


def stream(items, *, finish=True):
    data = b"".join(wire.packet(wire.header(i, kind, len(payload)), payload)
                    for i, (kind, payload) in enumerate(items))
    return data + (wire.end(len(items)) if finish else b"")


def complete(baseline=None):
    return [("HTTP_RECORD", http()), ("LOAD_RECORD", load()),
            ("CAPTURE_RECORD", capture(baseline)), ("SCREENSHOT_PNG", wire.png_1x1())]
