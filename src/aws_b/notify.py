"""AWS-B direct notification: state changes become events, events are queued on HEAD, then published to SNS.

Current state and unsent events are kept apart (`obs_state` vs `ntf_pending` on the CONTROL item):

    PASS -> FAIL (SNS down) -> PASS     the FAIL event stays queued and is sent by a later run,
                                        followed by the recovery event; nothing is overwritten.

Order inside one run: (1) the observation and the new event are written in ONE conditional update,
(2) each queued event is published oldest first, (3) after each publish it is removed from the queue
by a conditional update. A stop, a newer slot or a new generation fails (1) and (3), so a stopped or
superseded run never publishes more.

Not exactly-once: SNS Publish and the DynamoDB write cannot share a transaction. A crash after a
publish but before (3) re-sends that event on the next run (duplicate, never a loss). A successful
Publish does not prove the mail was delivered. A stop landing between (1) and the Publish itself
cannot be prevented.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Callable, Optional

from .store import Claim

# A longer backlog never drops an event silently: the oldest ones are folded into ONE queued SUMMARY event
# (count and time span), which is mailed like any other event.
MAX_PENDING = 10

# (previous, current) -> kind. Equal states and a first PASS produce no event.
_KIND = {("PASS", "FAIL"): "FAILURE", ("UNKNOWN", "FAIL"): "FAILURE",
         ("FAIL", "PASS"): "RECOVERY", ("UNKNOWN", "PASS"): "CONFIRMED",
         ("PASS", "UNKNOWN"): "UNKNOWN", ("FAIL", "UNKNOWN"): "UNKNOWN"}
_FIRST = {"FAIL": "FAILURE", "UNKNOWN": "UNKNOWN"}
_SUBJECT = {"FAILURE": "FAIL", "RECOVERY": "RECOVERED", "CONFIRMED": "OK", "UNKNOWN": "UNKNOWN",
            "SUMMARY": "SUMMARY"}
_HEADLINE = {"FAILURE": "障害を検知しました", "RECOVERY": "復旧しました",
             "CONFIRMED": "正常を確認しました", "UNKNOWN": "判定できませんでした",
             "SUMMARY": "未送信の通知をまとめました"}
_STATE_JA = {"PASS": "正常", "FAIL": "障害", "UNKNOWN": "判定不能"}


def transition_event(previous: Optional[str], state: str, *, target_id: str, slot: str,
                     reason: str, http_status: Optional[int], at: str) -> Optional[dict[str, Any]]:
    kind = _FIRST.get(state) if previous is None else _KIND.get((previous, state))
    if kind is None:
        return None
    return {"kind": kind, "target_id": target_id, "previous": previous, "state": state,
            "slot": slot, "reason": reason, "http_status": http_status, "at": at}


def _summary(target_id: str, folded: list[dict[str, Any]], *, unreadable: bool = False) -> dict[str, Any]:
    """One event standing in for `folded` events that could not be kept (or for an unreadable queue)."""
    last = folded[-1] if folded else {}
    count = None if unreadable else sum(e.get("count", 1) if e["kind"] == "SUMMARY" else 1 for e in folded)
    return {"kind": "SUMMARY", "target_id": target_id, "previous": None,
            "state": last.get("state", "UNKNOWN"), "count": count,
            "first_slot": (folded[0].get("first_slot") or folded[0]["slot"]) if folded else None,
            "slot": last.get("slot", ""), "at": last.get("at", ""),
            "reason": "QUEUE_UNREADABLE" if unreadable else "QUEUE_OVERFLOW", "http_status": None}


def fold_overflow(queue: list[dict[str, Any]], target_id: str, limit: int = MAX_PENDING
                  ) -> tuple[list[dict[str, Any]], int]:
    """Keep at most `limit` events by folding the oldest into one SUMMARY. -> (queue, events folded)."""
    if len(queue) <= limit:
        return queue, 0
    take = len(queue) - limit + 1               # +1: the summary itself takes one place
    folded, rest = queue[:take], queue[take:]
    summary = _summary(target_id, folded)
    return [summary] + rest, summary["count"]


def parse_pending(text: Any) -> tuple[list[dict[str, Any]], bool]:
    """-> (events, valid). A missing attribute is a valid empty queue."""
    if text is None:
        return [], True
    try:
        events = json.loads(text)
    except (TypeError, ValueError):
        return [], False
    if not isinstance(events, list) or not all(isinstance(e, dict) for e in events):
        return [], False
    return events, True


def dump_pending(events: list[dict[str, Any]]) -> str:
    return json.dumps(events, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def format_message(event: dict[str, Any], hostname: str, path: str) -> tuple[str, str]:
    """-> (subject, body). The subject stays ASCII (SDK docs for SNS Subject); the body is Japanese."""
    subject = f"[SiteProof] {_SUBJECT[event['kind']]} {event['target_id']}"[:99]
    status = event.get("http_status")
    if event["kind"] == "SUMMARY":
        count = event.get("count")
        body = "\n".join([
            f"SiteProof 監視: {_HEADLINE['SUMMARY']}",
            "",
            f"対象ページ : {event['target_id']} (https://{hostname}{path})",
            f"まとめた通知: {count if count is not None else '不明(未送信キューを読み取れませんでした)'}件",
            f"対象期間   : {event.get('first_slot') or '(不明)'} 〜 {event.get('slot') or '(不明)'} (UTC)",
            f"その時点の最後の状態: {_STATE_JA.get(event.get('state'), '(不明)')}",
            "",
            "※ SNSへ送れない状態が続き、保存できる未送信通知の上限を超えたため、古い通知を1通にまとめました。",
            "※ 以降の通知は個別に送られます。現在の状態は次のメールまたは監視画面で確認してください。",
        ])
        return subject, body
    body = "\n".join([
        f"SiteProof 監視: {_HEADLINE[event['kind']]}",
        "",
        f"対象ページ : {event['target_id']} (https://{hostname}{path})",
        f"状態       : {_STATE_JA.get(event.get('previous') or '', '(初回)')} → {_STATE_JA[event['state']]}",
        f"HTTPステータス: {status if status is not None else '(応答なし)'}",
        f"発生時刻   : {event['at']} (UTC) / 監視スロット {event['slot']}",
        f"理由       : {event['reason']}",
        "",
        "※ このメールは状態が変わったときだけ送られます。送信に失敗した通知は次回の監視実行で再送されます(重複することがあります)。",
        "※ SNSへの送信成功は、メールの受信完了を保証するものではありません。",
    ])
    return subject, body


def process(store: Any, claim: Claim, head: Optional[dict[str, Any]], *, state: str, reason: str,
            http_status: Optional[int], finished_at: str, hostname: str, path: str,
            publish: Callable[[str, str], None], now: Callable[[], datetime],
            absolute_end_at: datetime) -> dict[str, Any]:
    """Observe, queue and send. -> {ok, reason, sent, pending, dropped}; ok means nothing is left unsent.

    `dropped` counts events folded into a SUMMARY this run (they are still mailed, as one summary).
    """
    out: dict[str, Any] = {"ok": False, "reason": "", "sent": 0, "pending": 0, "dropped": 0}
    head = head or {}
    pending, valid = parse_pending(head.get("ntf_pending", {}).get("S"))
    previous = head.get("obs_state", {}).get("S")
    event = transition_event(previous, state, target_id=claim.target_id, slot=claim.scheduled_slot,
                             reason=reason, http_status=http_status, at=finished_at)
    if not valid:                               # unreadable queue: say so in a mail instead of resetting silently
        pending = [_summary(claim.target_id, [], unreadable=True)]
    queue, out["dropped"] = fold_overflow(pending + ([event] if event else []), claim.target_id)
    text = dump_pending(queue)
    observed = store.observe(claim, state, text)
    if not observed.ok:
        out.update(reason=observed.reason, pending=len(queue))
        return out
    stored_text = text
    while queue:
        if now() >= absolute_end_at:
            out.update(reason="PAST_ABSOLUTE_END", pending=len(queue))
            return out
        subject, body = format_message(queue[0], hostname, path)
        try:
            publish(subject, body)
        except Exception as exc:
            out.update(reason="PUBLISH_FAILED:" + type(exc).__name__, pending=len(queue))
            return out
        out["sent"] += 1
        rest = queue[1:]
        text = dump_pending(rest)
        marked = store.set_pending(claim, text, stored_text)
        if not marked.ok:
            # Already published: a later run may send it again, but nothing more is sent now.
            out.update(reason=marked.reason, pending=len(queue))
            return out
        queue, stored_text = rest, text
    out.update(ok=True, reason="NOTIFIED" if out["sent"] else "NO_CHANGE", pending=0)
    return out
