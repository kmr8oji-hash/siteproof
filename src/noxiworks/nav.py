"""One shared top menu for all six screens (HOME, REVIEW, DETAIL, ACTIVITY, EVIDENCE, AWS OPERATIONS).

Pure markup; no dependency on the other modules, so the static AWS OPERATIONS page can use it too.
"""
from html import escape

ITEMS = (('home', 'index.html', 'HOME'), ('review', 'review.html', '差分レビュー'),
         ('details', 'details.html', 'DETAIL'), ('activity', 'activity.html', '履歴・通知'),
         ('evidence', 'evidence.html', '証拠一覧'), ('operations', 'aws-operations.html', 'AWS運用'))


def global_nav(current):
    links = ''.join(
        f'<li><a href="{href}" data-nav="{key}"' + (' aria-current="page"' if key == current else '') + f'>{escape(label)}</a></li>'
        for key, href, label in ITEMS)
    return f'<nav class="global-nav" aria-label="画面メニュー"><ul>{links}</ul></nav>'
