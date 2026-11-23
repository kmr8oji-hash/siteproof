# 監視実測データのアーカイブ（DynamoDB TTL 14日対策）

実装: `src/noxiworks/archive.py` / テスト: `tests/test_archive.py`。AWSへは書き込まない。

## 何を保存するか

| 種別 | 保存内容 | 公開 | 非公開(`private/`) |
|---|---|---|---|
| 監視結果 | スロット日時・HTTP状態・応答時間・判定(PASS/FAIL/UNKNOWN)・理由・TLS期限・取得日時 | `public/runs/<target>.jsonl` | DynamoDB生項目（attempt_id・接続先IP等を含む） |
| 障害・復旧 | FAILの連続区間と復旧時刻（記録から導出） | `public/incidents.json` | — |
| アラーム履歴 | CloudWatchの状態遷移（対象・種別・時刻・OK/ALARM・理由） | `public/alarm_events.json` | 生の履歴（アラーム名を含む） |
| 要約・検証 | 件数・可用率・先頭/末尾スロット・各ファイルのSHA-256・バッチ一覧 | `MANIFEST.json` `SHA256SUMS.txt` `index.html` | `batch.json` |

`private/` は公開しない。`public/` にはアカウントID・テーブル名・アラーム名・ARN・IPを書かない（テストで確認）。

## しくみ

- 取得1回 = 不変の「バッチ」1つ（`private/batches/<id>/`）。既存バッチは書き換えない。
- `public/` は全バッチから毎回再生成する（同じ内容の再取込は `ALREADY_IMPORTED`、重複スロットは1件に統合、CLAIMED→RECORDEDは更新、食い違いは `conflicts` に記録し先着を保持）。
- 検証: `verify` が全バッチのSHA-256・件数と、公開ファイルが再生成結果と一致することを確認する。`SHA256SUMS.txt` は `sha256sum -c` でも確認できる。
- AWS停止後の閲覧: `public/index.html`（静的）、または `snapshot` でHOME入力を作る（`python -B -m src.noxiworks --snapshot FILE --out NEW_DIR`）。

## 操作

```
# ローカル証拠の取込（AWS不要）
py -3.15 -B -m src.noxiworks.archive import-snapshot --archive DIR FILE [FILE ...]
py -3.15 -B -m src.noxiworks.archive import-alarm-history --archive DIR FILE [...]
# 検証 / 再生成 / HOME入力
py -3.15 -B -m src.noxiworks.archive verify  --archive DIR
py -3.15 -B -m src.noxiworks.archive rebuild --archive DIR
py -3.15 -B -m src.noxiworks.archive snapshot --archive DIR --out NEW_FILE.json
# AWS読取（要・別途承認。既存の D: 認証環境が必要）
py -3.15 -B -m src.noxiworks.archive fetch --archive DIR --config refresh-config.json --aws-read [--alarm-history]
```

`fetch` が使うAWS読取: DynamoDB `Query`（`RUN#<target>`、全ページ、2回目以降は前回最終スロットの1時間前から）と `GetItem`（`CONTROL#<target>`）。`--alarm-history` を付けた場合のみ CloudWatch `DescribeAlarmHistory`（15アラームを名前指定）。

## 運用

- 最初の削除（TTL）は 2026-11-29 頃から始まる。**2026-11-28 より前に初回 `fetch`**、その後は週1回。
- `public/` は公開用データ、`private/` は手元保管。アーカイブ全体は別媒体にもコピーすること（`.local` は未追跡）。
