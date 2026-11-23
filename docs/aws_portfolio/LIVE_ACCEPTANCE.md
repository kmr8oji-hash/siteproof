# LIVE実証の受入基準

> **履歴注記(2026-11-13)**: 本文はAWS-B限定LIVE実証**前**の記録で、当時の状態(未デプロイ／LIVE NO-GO等)を保存している。AWS-Bは2026-11-12に限定LIVE実証を完了し、同日に対象Trialの停止・撤収を実施した。継続本番監視は未開始。最新の実証結果は [EVIDENCE_INDEX.md](EVIDENCE_INDEX.md) §0 を参照。過去の記録本文は書き換えていない。

オフラインのテスト結果はここでの合格にならない。各項目は、AWS上で直接観測した証拠が揃ったときだけ `AWS_VERIFIED` とする。未実施は `NOT_RUN`、判定不能は `UNKNOWN` のまま記録する。失敗した試行の記録は書き換えない。

## 共通の前提

- 対象ごとに、期間・費用の目安・影響範囲・停止条件・試行回数を明記したUSER承認がある。
- 実行したコマンド、時刻(UTC)、応答、テンプレートとバンドルのSHA-256を保存する。
- 公開資料ではアカウントID・メールアドレス・実リソースIDを伏せる。

## 運用ガード / AWS-A

| ID | 実測内容 | 証拠 | 合格条件 | 現状 |
|---|---|---|---|---|
| G1 | ガードスタックの作成 | 変更セット、スタックイベント | 想定資源のみ作成。AWS-Aに変更なし | NOT_RUN |
| G2 | Alarm強制発火 → メール到達 → OK復帰 | Alarm履歴、受信メールの時刻 | ALARM/OKとも到達 | NOT_RUN |
| G3 | Budgets通知 | 通知設定の読戻し、受信メール | 閾値超過後に到達。未到達は NOT_TESTED のまま | NOT_RUN |
| A1 | HTTPS、ルート302、S3直アクセス拒否、未許可キー拒否、ヘッダ | curl出力 | テンプレート定義と一致 | 過去報告あり・今回未実測 |
| A2 | 配信の無効化 → 伝播 → 再有効化 | 時刻つきcurl、Distribution状態 | 無効時に配信不可。所要時間を記録 | NOT_RUN(別承認) |

## AWS-B

| ID | 実測内容 | 証拠 | 合格条件 |
|---|---|---|---|
| B-01 | 24〜72時間の連続稼働(絶対期限つき) | RUN項目、メトリクス | 欠落slotが説明可能。重複probe 0 |
| B-02 | 重複イベント(RUNBOOK B1) | 判定ログ、RUN項目 | probe 1回、`DUPLICATE_SLOT` |
| B-03 | 遅延・逆順(B2, B3) | 判定ログ | `EVENT_TOO_OLD` / `OLDER_SLOT`、probe 0回 |
| B-04 | 停止後の拒否(B4, B5, B9) | 判定ログ、起動数メトリクス | 停止後のprobe 0回 |
| B-05 | 保存失敗(B6) | `Unpersisted` メトリクス、Alarm、メール | UPが記録されない。再probe 0回 |
| B-06 | 対象ダウンと復旧(B7) | メール2通、Alarm履歴 | 遷移時のみ通知 |
| B-07 | 絶対期限(B8) | 判定ログ、Schedule状態 | 期限後のprobe 0回 |
| B-08 | IAM負例(B10) | AccessDeniedの記録 | 許可外操作がすべて拒否 |
| B-09 | 実費と残余資源 | Cost Explorer、資源一覧 | 見積との差を説明。残余が一覧と一致 |

すべて現状 NOT_RUN。

## AWS-C(fixtureのみの初回Pilot)

| ID | 実測内容 | 証拠 | 合格条件 |
|---|---|---|---|
| C-01 | ガード面が先に稼働 | `WatchdogRun` メトリクス、Alarm状態 | Worker作成前にWatchdogが報告済み |
| C-02L | 単一起動 | CloudTrail(RunInstances 1回、StartInstances 0回) | 起動イベントが1回だけ |
| C-03 | EC2上の隔離(既存ハーネス) | `preflight.json`、DROPカウンタ、canary差分 | 禁止先到達0。未実施項目はUNKNOWN |
| C-04 | 実IMDS・VPC DNSへの到達拒否 | 追加負例の結果 | 到達0(手順は未実装) |
| C-05 | 証拠の公開 | `run-manifest.json`、S3チェックサム、読戻し | 全オブジェクト一致、マニフェストが最後に存在 |
| C-06 | 上書き拒否 | 無条件PUT・同一キー再PUTの応答 | いずれも拒否 |
| C-07 | 署名(有効時) | 署名エンベロープ、KMS Verify、CloudTrail | VALID。改変したマニフェストはINVALID |
| C-08 | 正常終了 | Describe、制御状態 | `terminated`、`TERMINATED_VERIFIED`、ボリューム・ENI残存なし |
| C-09 | Watchdogによる終了(Workerを故意に待機させる) | Watchdogログ、CloudTrail | 期限でTerminate。他インスタンスへの操作0 |
| C-10 | DynamoDB不通相当でも終了 | 同上(制御テーブルへの権限を外す等) | Terminateが実行される |
| C-11 | 曖昧な対象 | 同じタグの2台目を作らずに検証する方法は未定 | 未定(オフライン試験のみ) |
| C-12 | 実費と残余資源 | Cost Explorer、資源一覧 | 見積との差を説明。残余が一覧と一致 |

すべて現状 NOT_RUN。`C-02L` はLIVE受入項目の番号で、設計上のGate「C-02(再arm競合)」とは別。Gate C-02は DEFERRED / OPEN のまま。

## 合格しても主張しないこと

- 撮影結果の品質PASS(`quality=UNKNOWN`、`PROFILE_UNATTESTED` は維持)。
- 反復運用の安全性(初回1回の観測のみ)。
- 実サイト撮影(未実装)。
- ネットワーク層でのホスト名単位の出口制御(Bはアプリ層、CのAWS層はポート単位)。
- 費用の上限。
