# AWS-B Lite（低頻度・低コストHTTP監視）

**状態（2026-11-22 時点）**：実AWSでの検証は **Stage A（1実ページ＋一時fixture）まで**。Stage B（残り4ページ）は**未実施・未承認**です。6時間・12時間間隔は **LIVE未検証**、AWSの実請求額は **UNKNOWN** です。5実ページの停止は **2026-11-27 12:00 JST に予定**しており、この文書の時点では**停止済みではありません**。

> **公開リポジトリだけでAWS-B Liteを再現構築することはできません。** 構築に使った生成スクリプト、IAMの適用文書、運用スクリプト（arm・停止・状態確認）は、AWSアカウント情報を含むため公開していません。公開しているのは、CloudFormationテンプレート、Lambdaのコード、テスト、設計の説明です。詳しくは「公開範囲と再現性」を参照してください。

## 構成

```
Scheduler（rate 6h／12h。Stage Aの試験は900秒）→ ページ別Lambda → DynamoDB（CONTROL#HEAD / RUN#）
                                   │
                                   ├ 状態変化 → SNS Publish（既存トピック）→ メール
                                   └ 保存と通知が完了 → ProbeCompleted（EMF, MonitorGroup）→ 集約Heartbeat Alarm → 既存SNS
```

従来のAWS-Bは、ページごとにAlarm 3本とカスタムメトリクス4個を持っていました。Liteはこれを、**集約Heartbeat Alarm 1本とメトリクス1系列**に置き換えます。HTTP検査、UNKNOWN判定、条件付き確保、世代、絶対期限、停止制御は変更していません。

| 要素 | 実体（公開ファイル） |
|---|---|
| ページ別の監視スタック | `infra/aws_b/template.json`（DynamoDB、Lambda、Scheduler、IAMロール） |
| 集約Heartbeat Alarm | `infra/aws_b/health.json`（Alarm 1本のみ。パラメータ `ExpectedPages` ほか） |
| ハンドラ・状態・通知 | `src/aws_b/handler.py`、`store.py`、`notify.py`、`probe.py` |
| 独立Stopper（**未適用**） | `src/aws_b/stopper.py`、`infra/aws_b/stopper.json`（現行IAMではデプロイ不可。コードのみ） |

## 状態の管理（DynamoDB）

- `CONTROL#<対象>/HEAD`：有効／無効、実行世代、ポリシー版、最後に観測した状態（`obs_state`）、未送信の通知（`ntf_pending`）。
- `RUN#<対象>/<slot>`：1回の検査結果（HTTP状態、判定、理由、接続先IP、TLS期限）。TTLは14日です。
- 確保は条件付き書込み1回です。重複した配信、逆順、停止後、世代違いは、外への接続より前に拒否されます。

## 通知（`src/aws_b/notify.py`）

- 遷移：PASS→FAIL 障害／FAIL→PASS 復旧／PASS→UNKNOWN・FAIL→UNKNOWN 判定不能／UNKNOWN→PASS 正常確認／UNKNOWN→FAIL 障害。同一状態と初回PASSは通知しません。初回のFAIL・UNKNOWNは通知します。
- 1回の実行：①観測結果とイベントを1回の条件付きUpdateで保存 → ②古い順にPublish → ③送信ごとに条件付きUpdateでキューから除去。①③の条件は「有効かつ世代一致かつ自分が最新の確保の持ち主」で、停止・新しいスロット・新世代では書けず、以後は送信しません。Publish前に絶対期限も再確認します。
- `PASS → FAIL（SNS失敗）→ PASS` でも、FAIL通知は残り、次の実行でFAIL→復旧の順に送られます。
- **完全なExactly Onceではありません。** Publish成功後・除去前に止まると、次の実行で同じ通知が重複します（消失はしません）。①の後・Publishの前に停止が入る競合は防げません。Publish成功はメール受信を保証しません。
- 未送信が10件を超えても捨てません。古いものを1件の `SUMMARY` イベント（件数・期間・最後の状態）に畳み込み、SNS復旧後にメールします。
- SNS Subjectは英数字のみ、本文は日本語です。

## 集約Heartbeat（`ProbeCompleted`）

- 送信条件：結果をDynamoDBに保存でき、かつ未送信の通知が残っていない実行だけ。UNKNOWNも「完了」なら送ります。拒否（重複・停止・期限切れ）、保存失敗、SNS失敗では送りません。Lambdaの `Invocations` は使いません。
- 名前空間 `SiteProof/Monitor`、ディメンション `MonitorGroup`（全ページ共通）の1メトリクスのみ。タイムスタンプは実行時刻ではなく**スケジュールスロット**です。
- health Alarm：`Sum < ExpectedPages`、周期はスケジュール間隔、3期間中2期間、欠測は異常（breaching）、警報と復旧を既存SNSへ送ります。
- **既知の制約**
  - **Alarmの位相**：Stage Aの実測では、評価窓の端が2つのスロットの間に入ると、**欠測1回でも発報する場合**がありました（検知まで約16分）。「連続2回の欠測で警報」という設計モデルより早く発報します。正常観察74分では誤報はありませんでしたが、誤報がないことの証明ではありません。
  - 計画停止も欠測になります。停止時はAlarmのアクションを無効にするか、`ExpectedPages` を減らします。**このAlarmは全ページで共有**のため、1ページだけの停止にAlarmのアクション停止を使うと、他ページの欠測通知も止まります。
  - **同一期間の重複計上**：スロットごとにHeartbeatは1点だけ（テスト済み）ですが、Scheduleの位相を変える操作（DISABLED→ENABLEDなど）で1ページが1周期に2点を送ると、別ページの欠測1点を相殺しうるという課題が残っています。
  - `ExpectedPages` は静的です。1ページを恒久的に止めるときは、healthスタックの `ExpectedPages` を減らします。
  - 集約方式が成立しない場合の代替案：ページ別Heartbeat（Alarm 5本、メトリクス5個）。独断では切り替えません。

## 監視の開始・停止・撤収

開始：**二段階**です。スタック作成だけでは監視は始まりません。①スタック作成（`ScheduleState=DISABLED`）→ ②運用者が制御項目をarm（条件付き作成）→ ③`ScheduleState=ENABLED`。healthスタックは、作成時に `AlarmActionsEnabled=false`（初期の欠測による誤報を避ける）、正常になったことを確認してから有効にします。

停止：3層で、どれか1つでprobeの開始が止まります（制御項目を無効にして世代+1／Scheduleを無効に／予約同時実行数を0に）。加えて、**絶対期限**（Lambdaの環境変数）とScheduler `EndDate` が、期限後の実行を止めます。AWS内の独立Stopper（層C）は**未適用**で、**完全な自律停止は未完成**です。

撤収：停止を確認し、必要な記録をエクスポートし、スタックを削除します。`ProbeTable` と一部の資源は **Retain** で残ります。削除は別途承認が必要で、削除してもゼロ課金とは限りません。

公開ファイルだけを使う手順は [RUNBOOK_AWS_B_LITE.md](RUNBOOK_AWS_B_LITE.md)（第三者環境では未実証）にあります。[RUNBOOK_AWS_B.md](RUNBOOK_AWS_B.md)（Lite導入前の記録）と [AWS_B_PRACTICAL_LIVE.md](AWS_B_PRACTICAL_LIVE.md) は、非公開の生成スクリプトや運用スクリプトを前提にした部分があり、**そのままでは実行できません**。

**予定：5実ページは 2026-11-27 12:00 JST（03:00:00Z）に停止します。** 設定済み（Lambdaの絶対期限とScheduler EndDate）ですが、この文書の時点では実施前であり、停止を確認した記録はありません。停止後は、旧構成のページ別Alarmなどが欠測を検知してメールを送る見込みです（停止の結果であり、サイトの障害ではありません）。

## IAM（最小権限）

公開しているテンプレートの範囲（`infra/aws_b/template.json`）：

| ロール | 許可 |
|---|---|
| probeロール | DynamoDB `UpdateItem`・`PutItem`（自分のテーブルのみ。キー条件つき）、Logs `CreateLogStream`・`PutLogEvents`（自分のロググループのみ）、`sns:Publish`（**既存トピック1つだけ**） |
| Schedulerロール | `lambda:InvokeFunction`（自分のprobe関数のみ） |

読み取り（`GetItem`）、削除、他テーブル、他の宛先への書込みは許可していません。Lambdaは同時実行1、256MB、20秒、arm64です。

運用者（人）側のIAM（変更セット用の最小権限、Permissions Boundaryの更新）は、アカウント情報を含むため公開していません。方針は次のとおりです。変更セット用は対象スタックに限った4アクションだけ（`ListChangeSets`・スタック削除・IAM管理は含めない）、Boundaryは運用者に `iam:CreatePolicyVersion` を与えず、利用者が更新文書を1回だけ適用します。

## 実証状況

### 実測した範囲：Stage A（2026-11-21、1実ページ＋一時fixture、15分間隔）

詳細な証拠区分は、非公開の記録に保存しています。ここでは結果の要約です。

| 項目 | 結果 |
|---|---|
| Liteの実行とHeartbeat | PASS。health Alarmは初期の欠測から正常（OK）へ遷移 |
| 正常時の誤報 | 約74分の観察で0件（計画の3時間には満たない） |
| 障害検出と通知 | 一時fixtureをHTTP 503にするとFAIL判定、SNS Publish成功、メール受信。次の周期は重複通知なし。200へ戻すと復旧通知1通 |
| SNS失敗時の保留・再送 | トピックへの送信を拒否した状態で503→200を挟むと、FAILと復旧が保留され、Heartbeatは止まり、Alarmが作動。トピック復旧後の次の実行で2件を順に送信し、キューが空に戻り、Heartbeatが再開 |
| 管理セッション非依存 | 管理側のAWSセッションを無効にした約1時間のあいだも、Lambda監視・DynamoDB保存・Heartbeat・障害メールは継続（管理側からの読取は21回失敗） |
| 停止 | fixtureのページ単位の停止（制御項目無効・世代+1・Scheduler無効・同時実行0）を実行し、読み戻しで一致を確認。通常の5ページは稼働を継続 |
| メール | Stage Aの通知メール8通の受信を利用者が確認 |

### 未検証・未実施（PASSにしません）

- **Stage B（残り4ページのLite化）は未実施・未承認**です。現在のAWS上で、Liteで動いている実ページは1つだけで、残り4ページは旧構成のページ別Alarmのままです。
- **6時間・12時間間隔は LIVE未検証**です（Stage Aは15分間隔）。6h/12hでのAlarmの評価は、確認に24時間以上かかります。
- **UNKNOWN通知は LIVE未検証**です（fixtureでは発生させられません）。
- **Schedulerを止める試験は未実施**です（Heartbeatの欠測は、SNSの失敗で作り、検知を実測しました）。
- **AWSの実請求額は UNKNOWN** です（運用者に請求情報を見る権限がありません）。
- 独立Stopper（層C）は未適用です。

## 費用の目安（推定。実請求ではない）

条件：us-east-1、5ページ、6時間間隔、30日間、無料枠・クレジット・税なし。

| 項目 | 月額（USD） |
|---|---:|
| カスタムメトリクス1個（`ProbeCompleted`） | 0.30（上限） |
| 標準Alarm 1本 | 0.10 |
| Lambda arm64 256MB、約600回×3秒 | 0.006 |
| DynamoDB書込み 約2,400件 | 0.002 |
| Scheduler 600回、SNS、Logs 約1MB | 0.002未満 |
| **合計** | **約 0.41** |

- メトリクスの0.30は、ひと月分の**上限**です。時間按分で課金される場合は、この項目が小さくなり、合計は約0.16になりえます。ただし、按分が成立する条件（データのある時間帯だけ課金されること）を確認できていないため、**0.16は参考値**で、本書の見積には使いません（[SYNTHETICS_COMPARISON.md](SYNTHETICS_COMPARISON.md)）。
- Stage Aの試験（15分間隔、一時fixture）や、**旧構成のAlarm・メトリクスなど、残っている資源**の費用は、この表に含みません。別途の費用が発生しえます。
- CloudWatch Syntheticsとの比較は [SYNTHETICS_COMPARISON.md](SYNTHETICS_COMPARISON.md) にあります。

## 旧Alarmと更新時の注意

- 既存スタックからページ別の3 Alarmをテンプレートで外すと、CloudFormationはスタックから外すだけで、**Alarm自体はAWSに残ります**。
- 残ったAlarmは、`ProbeFailure` や `ProbeUnknown` が来なくなり、`UnpersistedAlarm`（欠測は異常）が鳴り続け、通知と費用（1本あたり月約0.10）の両方になります。**更新の前に通知を止め、確認してから別途削除します。**
- `-function-error` AlarmはLambdaの `Errors` を見ているため、更新後も有効で、Lambda異常の追加の目として残します。
- 更新後の最初の実行は、`obs_state` が無いので初回扱いです。PASSは無通知、FAIL・UNKNOWNは通知されます。

## 公開範囲と再現性

| 必要なもの | 公開 |
|---|---|
| CloudFormationテンプレート（`template.json`、`health.json`）、Lambdaコード、テスト | 公開 |
| テンプレート生成スクリプト（アカウント・Trial固有の値を入れる） | **非公開** |
| 運用者のIAM適用文書（変更セット権限、Boundary更新） | **非公開** |
| 運用スクリプト（arm、停止、状態確認、通知トピックの切替） | **非公開** |
| 通知用SNSトピックとメール購読、コード用S3 | 手動で用意（テンプレートには含まれません） |

- **Lambdaバンドル**：公開の `tools/build_bundles.py` は `src/aws_b/notify.py` を含みます（Lite対応。以前は欠けていました）。作成したバンドルをアーカイブだけから読み込み、ハンドラをimportできることをテスト（`tests/aws_c/test_bundles.py`）で確認しています。Stage Aで実際に使ったバンドルは非公開の作成スクリプトで作ったもので、公開のビルダーの出力と同一かは照合していません。
- **導入手順**：公開ファイルだけを使う構築・arm・停止・撤収の手順は [RUNBOOK_AWS_B_LITE.md](RUNBOOK_AWS_B_LITE.md) にあります。**第三者の環境では一度も実行していない未実証の手順**で、Stage Aは非公開の運用スクリプトによるLIVE実証です（別のものです）。
- **手順書でも補えていない操作**：運用者用のIAMポリシー文書（操作の種類の目安のみ・未検証）／停止後の再開（再arm。公開手順なし。新しいスタックで構築し直す）／停止の自動読み戻しと全ページ一括の操作／公開テンプレートそのものをAWSに適用した実績（Stage Aは生成スクリプトが出力したテンプレートで実施）／6時間・12時間間隔のLIVE検証。詳細は同書の§13。
- このため、本書の手順を第三者がそのまま実行できるとは主張しません。再現できるのは、設計・コード・テンプレートの内容の確認までです。

## 次の作業（未承認）

- Stage B：残り4ページを、変更セットで1ページずつLite化し、`ExpectedPages` を5へ変更する。
- 6時間・12時間間隔への変更（LIVE未検証）。
- 旧Alarm・fixtureの撤収（別承認）。
