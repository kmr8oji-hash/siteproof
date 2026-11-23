"""S2-B-VERIFY dead-man switch: an INDEPENDENT controller that ends the egress window whatever the Broker, Worker or host script do.

Runs in its own container (root, cap-drop ALL + NET_ADMIN, read-only root, no-new-privileges, seccomp) in the run's network namespace.
It shares no code path with the Grant Broker's decisions: it does not resolve, grant or read anything from the Worker. It only removes.

The window is closed (every SP_GRANT rule flushed, every egress_open rule deleted) when ANY of these happens:
  * its deadline passes                                  -> reason DEADLINE
  * its stdin reaches EOF (the host script died/closed)   -> reason EOF         (fail closed)
  * the host sends {"type":"close"}                       -> reason COMMAND
and it exits WITHOUT touching any rule on {"type":"cancel"} (the host already closed the window itself and says so).
Deleting a rule that is already gone is not an error; a rule that cannot be deleted IS reported and keeps the exit non-zero.
"""
import json
import os
import select
import subprocess
import sys
import time

from tests.runtime.netpolicy_hardened import call, egress_device, egress_rules, flush_grants, grant_rules


def close_window(device):
    flushed, removed, errors = 0, 0, []
    try:
        flushed = flush_grants()
    except Exception as exc:
        errors.append('flush:' + type(exc).__name__)
    for chain, spec in reversed(egress_rules(device)):
        try:
            call('iptables', '-w', '-C', chain, *spec)
        except subprocess.CalledProcessError:
            continue  # Already gone.
        try:
            call('iptables', '-w', '-D', chain, *spec)
            removed += 1
        except Exception as exc:
            errors.append('delete:' + type(exc).__name__)
    left = grant_rules()
    return {'flushed_grants': flushed, 'removed_rules': removed, 'errors': errors, 'grant_rules_left': left}


def out(obj):
    sys.stdout.write(json.dumps(obj, separators=(',', ':')) + '\n')
    sys.stdout.flush()


def main():
    config = json.loads(sys.stdin.readline())
    if config['netns'] != os.readlink('/proc/self/ns/net') or os.getuid() != 0:
        raise SystemExit('namespace mismatch')
    deadline_seconds = config['deadline']
    if type(deadline_seconds) not in (int, float) or not 1 <= deadline_seconds <= 120:
        raise SystemExit('deadline must be 1..120 seconds')
    device = egress_device(config)
    end = time.monotonic() + deadline_seconds
    out({'type': 'ready', 'deadline': deadline_seconds, 'device': device})
    reason = None
    while reason is None:
        wait = end - time.monotonic()
        if wait <= 0:
            reason = 'DEADLINE'
            break
        if not select.select([sys.stdin], [], [], min(wait, .5))[0]:
            continue
        line = sys.stdin.readline()
        if not line:
            reason = 'EOF'
            break
        kind = json.loads(line).get('type')
        if kind == 'cancel':
            out({'type': 'cancelled'})
            return
        if kind == 'close':
            reason = 'COMMAND'
    result = close_window(device)
    out({'type': 'closed', 'reason': reason, **result})
    if result['errors'] or result['grant_rules_left']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
