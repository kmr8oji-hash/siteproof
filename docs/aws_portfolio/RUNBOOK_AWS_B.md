# AWS-B(サーバーレス継続監視)Runbook

> **履歴注記(2026-11-13)**: 本文はAWS-B限定LIVE実証**前**の記録で、当時の状態(未デプロイ／LIVE NO-GO等)を保存している。AWS-Bは2026-11-12に限定LIVE実証を完了し、同日に対象Trialの停止・撤収を実施した。継続本番監視は未開始。最新の実証結果は [EVIDENCE_INDEX.md](EVIDENCE_INDEX.md) §0 を参照。過去の記録本文は書き換えていない。

状態: **OFFLINE CANDIDATE / AWS LIVE NOT VERIFIED / AWS-B LIVE NO-GO**。この手順は一度も実行されていない。コマンドは例で、プレースホルダ(`<...>`)を含む。この文書は何も承認しない。

## 1. 構成と役割

`EventBridge Scheduler → Lambda(probe)→ DynamoDB → CloudWatch Alarm → SNS(ops_guardの既存トピック)`

| 要素 | 実体 | 役割 |
|---|---|---|
| テンプレート | `infra/aws_b/template.json` | 10資源。Schedule既定は `DISABLED` |
| ハンドラ | `src/aws_b/handler.py` | 受理判定 → 確保 → probe → 記録 → メトリクス |
| 状態 | `src/aws_b/store.py` | `CONTROL#<target>/HEAD` と `RUN#<target>/<slot>` |
| probe | `src/aws_b/probe.py` | 既存 `src/isolation` の宛先ポリシーとIP固定接続を再利用 |
| 表示投影 | `src/aws_b/view.py` | UP / DOWN / UNKNOWN / STALE / STOPPED |

監視対象は自分が運用するCloudFront Preview(AWS-A)1件のみ。対象はデプロイ時に固定し、イベントからは渡せない。

## 2. 二段階の開始(スタック作成だけでは監視は始まらない)

1. スタック作成(`ScheduleState=DISABLED`)。この時点でprobeは0回。
2. 運用者が制御項目を作成する(arm)。条件 `attribute_not_exists` つきで、既存項目は上書きしない。
3. `ScheduleState=ENABLED` に更新する。

制御項目が無い、`enabled=false`、世代やポリシー版が不一致のいずれでも、ハンドラは接続前に拒否する。

### arm の例(`src/aws_b/store.build_arm_request` と同じ内容)

```
aws dynamodb put-item --table-name <TABLE> --region <REGION> \
  --item '{"pk":{"S":"CONTROL#preview"},"sk":{"S":"HEAD"},"enabled":{"BOOL":true},
           "execution_generation":{"N":"1"},"policy_version":{"S":"p1"},
           "target_hostname":{"S":"<TARGET_HOSTNAME>"},"armed_at":{"S":"<UTC>"}}' \
  --condition-expression "attribute_not_exists(pk)"
```

## 3. 停止(3層。どれか1つでprobe開始は止まる)

| 層 | 操作 | 効果 | 残る可能性 |
|---|---|---|---|
| 1. 制御項目 | `enabled=false` と世代+1を1回の条件付き更新で行う | 以後の確保がすべて失敗。キュー済みの旧世代イベントも拒否 | 実行中の1回(最大20秒) |
| 2. Schedule | `ScheduleState=DISABLED` | 以後の予定が発生しない | すでに発行されたイベント |
| 3. 同時実行数 | 予約同時実行数を0にする | 関数が起動しない | なし(即時) |

`AbsoluteEndAt` 到達後は、Scheduleの終了とハンドラ内判定の両方で自動的に止まる。課金がゼロになることは意味しない(§6)。

### 停止の例(`build_stop_request` と同じ内容)

```
aws dynamodb update-item --table-name <TABLE> --region <REGION> \
  --key '{"pk":{"S":"CONTROL#preview"},"sk":{"S":"HEAD"}}' \
  --update-expression "SET #en = :false, #gen = :next, #st = :at" \
  --condition-expression "attribute_exists(pk) AND #gen = :gen" \
  --expression-attribute-names '{"#en":"enabled","#gen":"execution_generation","#st":"stopped_at"}' \
  --expression-attribute-values '{":false":{"BOOL":false},":gen":{"N":"1"},":next":{"N":"2"},":at":{"S":"<UTC>"}}'
```

停止すると `ProbeFailureAlarm` は欠測を異常として発報する(監視が沈黙したことの検知)。意図した停止では、事前にアラームのアクションを無効化するか、通知を「停止による発報」と記録する。

## 4. LIVE障害注入手順(承認後)

各項目で、実行したコマンド、時刻、DynamoDBの該当項目、ログの判定行、メトリクス、通知メールを保存する。

| # | 注入 | 方法 | 成功条件 |
|---|---|---|---|
| B1 | 重複イベント | 同じ `scheduled_time` のペイロードで関数を非同期に2回起動 | probe 1回。2回目は `DUPLICATE_SLOT`。RUN項目は1件 |
| B2 | 遅延イベント | 61秒以上前の `scheduled_time` で起動 | `EVENT_TOO_OLD`。DynamoDB書込み0 |
| B3 | 逆順 | 新しいslotを先に、古いslot(60秒以内)を後に起動 | 後者は `OLDER_SLOT`。probe 1回 |
| B4 | 停止後 | §3の層1実施後に、旧世代のペイロードで起動 | `STOPPED`。probe 0回 |
| B5 | 世代不一致 | 再arm(世代2)後に世代1のペイロードで起動 | `GENERATION_MISMATCH` |
| B6 | 保存失敗 | 実行ロールから一時的に `dynamodb:PutItem` を外す(IAM変更のため別承認) | `RUN_RECORD_UNCERTAIN`、probe 0回、`Unpersisted=1` → `UnpersistedAlarm` → メール。`UpdateItem` を外した場合は確保自体が `CLAIM_UNCERTAIN` でprobe 0回 |
| B7 | 対象ダウン | `TargetPath` を存在しないパスにしたスタックで観測(本番Previewは止めない) | `HTTP_403/404` → FAIL → Alarm → メール。復旧でOK通知 |
| B8 | 絶対期限 | 短い `AbsoluteEndAt` で作成し、期限後に手動起動 | `PAST_ABSOLUTE_END`。Scheduleも発火しない |
| B9 | 同時実行0 | 予約同時実行数0にして起動 | スロットルされ起動しない |
| B10 | IAM負例 | 実行ロールで `DeleteItem` / 他テーブル / 他キーへの書込みを試行 | すべて AccessDenied |

オフラインでは B1〜B6・B8 に相当する判定を擬似DynamoDBで試験済み(`tests/aws_b/test_handler.py`)。サービス側の実挙動(再試行、イベント寿命、条件キー)は未実測。

## 5. 証拠

- 判定行: Lambdaログの1起動1行のJSON(`decision`, `reason`, `scheduled_slot`, `attempt_id`, `logical_run_key`)。
- 記録: DynamoDBの `RUN#` 項目(`state`, `outcome`, `reason`, `http_status`, `selected_ip`, `tls_not_after`)。
- 通知: 異常・復旧のメール(状態遷移時のみ。at-least-onceで、exactly-onceは主張しない)。
- 費用: Cost Explorerのタグ別(`Project=SiteProof`, `Component=AWS-B`)日次。反映遅延あり。

## 6. 撤収と残余資源

1. §3で停止し、起動数メトリクスが0であることを確認する。
2. 必要な項目をエクスポートする(`RUN#` はTTLで14日後に消える)。
3. スタック削除。**`ProbeTable` は Retain** のため残る。削除は内容確認後の別承認。
4. 残余の確認: テーブル、ロググループ(スタック削除で消える設定)、Alarm、Schedule、IAMロール、コード用S3オブジェクト。
5. 数日後に請求を再確認する。削除はゼロ課金を意味しない。

## 7. 未確認事項(LIVEまたは公式確認が必要)

- `<aws.scheduler.scheduled-time>` の実際の文字列形式(パーサは `YYYY-MM-DDTHH:MM:SSZ` のみ受理。形式が違えば全イベントを拒否する=安全側に倒れるが監視は成立しない)。
- Scheduler `EndDate` の受理形式、Scheduler→Lambdaの起動方式と再試行の実挙動。
- Lambdaの利用可能なPythonランタイム識別子(コードは3.11以上が必要)。
- 予約同時実行数をアカウントのクォータ内で確保できるか。
- `dynamodb:LeadingKeys` 条件が `UpdateItem`/`PutItem` に期待どおり効くか。
- VPC外LambdaからのIPv6到達性(リゾルバはIPv4を先に選ぶ)。
- 無料枠の適用可否と実費。

## 8. FAST TRACK LIVE承認枠（提案／未承認）

- Region: us-east-1。対象: USERが指定する本人所有の既存CloudFront hostname、通常パス `/home/index.html`。配信停止試験はしない。
- 稼働: armから最大60分、5分間隔、最大12予定＋手動検証最大8回。AbsoluteEndAtをarm直前のUTC時刻+60分に固定し延長しない。予約同時実行数1が確保できなければ起動しない。
- 費用: この短時間実証の追加費用目安はUSD 1以内を仮置き（料金未照合、保証上限ではない）。月額Budget USD 5、実績80%/予測100%でSNSメール通知。Budgetsの反映遅延があるので有人監視を継続。USD 1到達を観測、異常呼出数、宛先違反、通知未到達、権限拡張が必要な場合は停止。
- 通知: USER指定メール。必要なら新規ops_guard（EnableTrail=false）を作成。SNS確認リンクはUSERが確認する。通知経路の試験は明示的にALARM状態へ変更し、実際の欠測/失敗検知とは別の証拠にする。Budgets閾値の実配送は発生しなければ未検証のまま。
- AWS操作: 公式仕様/料金確認、STS GetCallerIdentity（既存認証の使用のみ）、対象CloudFront/SNS/クォータ/費用の読取り、CloudFormation validate-template/change set/create/execute、専用private S3コードバケットの作成・versioning・public access block・ZIP upload、AWS-Bと必要なops_guardの作成（限定IAMロール含む）、DynamoDB arm/read/stop、Lambda invoke/configuration/concurrency、Scheduler enable/disable、CloudWatch Alarm状態試験・ログ/メトリクス取得、SNS publish/subscribe、Budgets作成/参照、Cost Explorer参照。
- 異常検知: 新設AWS-B LambdaのTargetPathだけを一時的に存在しないパスへ変更して403/404を観測する。CloudFront側は変更しない。実際に失敗応答にならなければ異常検知PASSとしない。正常パスに戻す。重複payload再送と停止後の旧世代再送でprobe_started=falseを保存する。
- 停止: 制御項目enabled=false・世代+1、Schedule無効化、Lambda予約同時実行0。手動停止は絶対期限前でも実施可。ログ・DDB・実イベント・通知受信時刻・停止後拒否をローカルへ保存する。
- 撤収: 証拠保存後、この実証で新設したAWS-B/ops_guardスタックの削除まで承認に含める。Retainテーブルとprivateコードバケット/ZIPは7日保全（以後の削除は別承認）。既存公開サービス・既存SNS・既存スタックは削除しない。資格情報の作成/変更、commit/push/merge、AWS-C課金は含めない。
- 実請求: 反映前はPENDING。後日同範囲の読取りで実費を保存し、推定値と分ける。上限をAWS側で保証する設定はない。

現在のパーサは秒UTCとゼロミリ秒`.000Z`を同じslotへ正規化する。非ゼロ小数・offset・未知形式は拒否。実イベントの原文をLIVEで保存する。DynamoDB処理後にも期限を再計算し、DNS処理後に期限切れなら接続せず、接続timeoutも残時間に合わせる。DNS呼出自体は同期OS resolverのため独立したhard timeoutではなく、Lambdaの20秒timeoutが最終上限。
