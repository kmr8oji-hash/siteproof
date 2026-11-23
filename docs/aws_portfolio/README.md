# SiteProof — AWSポートフォリオ(A / B / C)

自分で運用するWebサイトの稼働と表示を検証し、証拠を残すツール「SiteProof」を題材に、AWSの設計・実装・セキュリティ・運用・障害対応・費用管理を示すためのポートフォリオ。

## 現在の状態

| 区分 | 内容 | 状態 |
|---|---|---|
| AWS-A | CloudFront＋非公開S3の静的公開 | 公開済み(過去のExecutor報告。今回未変更・未再測定) |
| 運用ガード | SNS、Budgets(通知のみ)、CloudFront Alarm、任意でCloudTrail | **オフライン完成 / LIVE未検証** |
| AWS-B | Scheduler→Lambda→DynamoDB→Alarmの軽量監視 | **2026-11-12に限定LIVE実証済み・撤収済み**(5ページ×2回=10件HTTP 200。継続監視ではない。証拠区分は[EVIDENCE_INDEX.md](EVIDENCE_INDEX.md) §0) |
| AWS-C | 単回使い切りEC2のBrowser Worker Pilot | **設計・オフライン段階 / LIVE NO-GO / 実装コードは今回の公開Commitに含まれない**。AWS-A/Bの実証成果とは別 |

以下の文書のうち、AWS-Bの「未デプロイ／LIVE NO-GO」の記述は2026-11-12以前の履歴であり、AWS-Bの最新状態は上表と [EVIDENCE_INDEX.md](EVIDENCE_INDEX.md) §0 を優先する。AWS-C LIVEはNO-GO、Gate C-02 は DEFERRED / OPEN のまま。

## 読む順番

| 文書 | 内容 |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | 構成図、判定フロー、状態遷移、既存資産との対応 |
| [TEST_RESULTS.md](TEST_RESULTS.md) | 限定16 PASSと過去の基準実行（既知FAIL 1件）と未実行の範囲 |
| [OPEN_ITEMS.md](OPEN_ITEMS.md) | 未解決リスク、公式確認が必要な事項、USER承認が必要な操作 |
| [LIVE_ACCEPTANCE.md](LIVE_ACCEPTANCE.md) | LIVE実証の合格条件と証拠 |
| [RUNBOOK_GUARD_AND_AWS_A.md](RUNBOOK_GUARD_AND_AWS_A.md) | ガード導入とAWS-A未検証項目の実測手順 |
| [RUNBOOK_AWS_B.md](RUNBOOK_AWS_B.md) | AWS-Bの開始・停止・障害注入・撤収 |
| [RUNBOOK_AWS_C.md](RUNBOOK_AWS_C.md) | AWS-Cの実行順序・停止3層・証拠検証・復旧 |
| [COST_ESTIMATE.md](COST_ESTIMATE.md) | 想定費用(すべて推定)と超過経路 |
| [EVIDENCE_INDEX.md](EVIDENCE_INDEX.md) | 過去の成功・失敗・BLOCKED・STOPの索引 |
| [INTERVIEW_POINTS.md](INTERVIEW_POINTS.md) | 面接で説明する技術的ポイント |

## リポジトリ内の配置

```
infra/ops_guard/   template.json, README.md              運用ガード(オフライン実装)
infra/aws_b/       template.json                         AWS-B
src/aws_b/         model, store, probe, handler, view
tests/aws_b/       handler, probe, store/view, claim変異, テンプレート契約テスト
tests/aws_guard/   運用ガードの契約テスト
tests/aws_fakes.py tests/cfn_contract.py                 擬似クライアント、契約テスト共通部品
docs/aws_portfolio/                                      この文書群
```

**AWS-Cの実装コード(`infra/aws_c/` `src/aws_c/` `tests/aws_c/`)と、配備バンドル作成などの補助ツール(`tools/`)は、この公開Git Commitに含まれない。** AWS-Cは設計・オフライン段階の資料(ARCHITECTURE.md、RUNBOOK_AWS_C.md)としてのみ公開し、LIVE実証済みとは扱わない(LIVE NO-GO)。AWS-A/Bの実証成果とは区別する。

既存の `src/` `tests/` `web/` `runtime/` `infra/public_web/` の既存部分は、この文書群の作成では変更していない。

## 再現手順(オフライン)

前提: Windows、Python 3.15(`py -3.15`)。外部通信・Docker・AWS資格情報は不要。

```
# AWS-Bの限定テスト(オフライン。AWSへ接続しない)
py -3.15 -B -m unittest discover -s tests/aws_b -t .
py -3.15 -B -m unittest discover -s tests/aws_guard -t .
```

テスト結果の区分は [TEST_RESULTS.md](TEST_RESULTS.md)(過去の実行記録。AWS-C関連の件数を含み、本Commitに含まれないコードの結果もある)を参照。
## 設計の要点

1. **AWS-Bの冪等性**は、制御項目への1回の条件付き書込みに集約した。重複・逆順・停止後のイベントは同じ書込みで拒否され、外向き接続の前に終わる。
2. **保存できなかった結果は成功として扱わない。** 再probeせず、UNKNOWNとして見せる。監視の沈黙はAlarmの欠測で検知する。
3. **AWS-Cの停止は3層**(OSタイマー、Watchdog、通知)で、互いに依存しない。Budgetsは停止機構に数えない。
4. **再armの経路を作らない。** 起動系の権限をどのロールにも与えず、スロットは解放せず、終了はTerminate(LIVE適用は別承認)。
5. **既存資産は書き換えない。** SQLite、write-once証拠、manifest、隔離ハーネスをそのまま使い、AWS固有の部分だけを薄いアダプタとして追加した。
6. **テンプレートは変異テストで守る。** 安全性の性質を1つ壊すと、対応するテストが落ちる。

## 主張しないこと

- AWS-CがAWS上で動作すること(LIVE NO-GO)。AWS-Bは2026-11-12の限定実証のみで、現在は撤収済み。
- 撮影結果の品質PASS(`PROFILE_UNATTESTED` / 品質UNKNOWN を維持)。
- 費用の上限(見積は推定、Budgetsは通知)。
- ネットワーク層でのホスト名単位の出口制御。
- 反復運用の安全性、実サイト撮影(未実装)。

料金は未実測。AWS-Bの再実行は別承認(AWS-B Runbook §8)。
