# AWS-C(単回使い切りBrowser Worker Pilot)Runbook

状態: **OFFLINE CANDIDATE / AWS LIVE NOT VERIFIED / AWS-C Worker Pilot NO-GO / C-02 DEFERRED・OPEN**。この手順は一度も実行されていない。インスタンスの作成・Terminate・課金・cleanupはすべて別途USER承認が必要で、この文書は何も承認しない。

> **公開範囲(2026-11-13)**: AWS-Cは設計・オフライン段階で、LIVE NO-GOです。AWS-Cの実装コード(infra/aws_c、src/aws_c、tests/aws_c)と補助ツールは、この公開Git Commitに含まれません。本Runbookは設計資料であり、AWS-A/Bの実証成果とは区別してください。

## 1. 構成

```
[guard stack: 先に配備]                         [worker stack: 作成と削除のみ]
 Controller Lambda ── reserve/status ─┐
 DynamoDB ControlTable (SLOT / PILOT#run) ◄──── EC2 1台(作成時に1回だけ起動)
 Watchdog Lambda ◄─ Scheduler at(deadline) + rate(5分)    │  OSタイマー: shutdown -h +N
        └─ DescribeInstances / TerminateInstances(タグ条件)│  既存M2ハーネス(fixtureのみ)
 S3 EvidenceBucket(条件付き書込みのみ) ◄──────────────────┘  既存SQLite/S1証拠 → write-once公開
 (任意)KMS署名鍵
```

| 要素 | 実体 |
|---|---|
| ガード面 | `infra/aws_c/guard.template.json`(19資源、EC2なし) |
| Worker | `infra/aws_c/worker.template.json`(SecurityGroup＋Instanceのみ)、`worker.stack-policy.json`(全Update拒否) |
| 起動スクリプト | `infra/aws_c/user_data.sh`(テンプレートと同一であることをテストで強制) |
| コード | `src/aws_c/`: `control` `controller` `watchdog` `worker_entry` `evidence` `s3_publisher` `signer` `linux_launcher` |

## 2. 停止の3層(互いに独立)

| 層 | 仕組み | 依存しないもの | 効かない場合 |
|---|---|---|---|
| 1 | 起動直後の `shutdown -h +MaxRuntimeMinutes`。OS停止=Terminate設定 | AWS API、DynamoDB、Lambda | OSがハングした場合 |
| 2 | Watchdog Lambda。期限に1回(`at()`)＋5分周期。タグ一致が1台のときだけTerminate | Worker、DynamoDB(記録は事後のbest-effort) | Lambda/Schedulerの障害、タグ未付与 |
| 3 | 費用通知・Alarm → 人が確認 | 上記すべて | 人が不在のとき |

Budgetsは通知であり、停止機構ではない(層3の一部)。Terminate方式とEBS削除は実装候補で、LIVE適用は別承認。

## 3. 「起動1回・再armなし」を成立させている箇所

- Controllerは `reserve` と `status` だけを持ち、EC2権限が無い(`ControllerRole` に ec2 アクションなし)。
- どのロールにも `RunInstances` / `StartInstances` / `StopInstances` / `RebootInstances` が無い(テストで強制)。
- `SLOT/SINGLETON` 項目は一度作られたら解放されない。別runのreserveは永久に失敗する。
- Workerは制御状態が `RESERVED` のときだけ開始する。再起動等で2回目に起動しても `NOT_RESERVED` で何もせず終了する。
- Workerスタックは作成と削除のみ。スタックポリシーで全Updateを拒否する(テンプレート更新によるインスタンス置換=2回目の起動を防ぐ)。
- 終了はTerminate。停止状態のインスタンスが残らないので、再Startの対象が無い。

C-02(同一インスタンス再armの競合)はこの構成では再armという操作が存在しない。ただしGate表示は **DEFERRED / OPEN のまま**とし、扱いはCommander/USERが裁定する。反復運用(ジョブごとの新規起動)は別Pilot・別承認。

## 4. 事前準備(すべて承認後)

1. `py -3.15 -B tools/build_bundles.py <新規ディレクトリ>` でバンドルを作る。`bundle-manifest.json` のSHA-256をレビューする。
2. バンドルをバージョニング有効なコード用バケットへ配置し、**オブジェクトVersionId**を控える。
3. ランタイムイメージ(`runtime/docker/Dockerfile`、同じcommit)をECRのプライベートリポジトリへ登録し、**ダイジェスト**を控える。ビルドは外部取得を伴うため別承認。
4. マシンイメージを用意する。DockerとPython 3.11以上＋boto3が入っていること。起動時には何もインストールしない。イメージの作成手順は未作成(未解決事項)。
5. `PilotRunId`、`HardDeadlineUtc`、`GuardEndAt`、Region、対象VPC/サブネットを決める。

## 5. 実行順序(承認後)

| 手順 | 操作 | 進む条件 | 満たさないとき |
|---|---|---|---|
| 1 | ガードスタック作成 | CREATE_COMPLETE | 中止、記録 |
| 2 | Watchdogの稼働確認 | `WatchdogRun` が1回以上、`NO_TARGET` を報告。`WatchdogSilentAlarm` がOK | **Workerを作らない** |
| 3 | AlarmをALARMへ強制して通知到達を確認 | メール受信 | Workerを作らない |
| 4 | Controllerへ `{"action":"reserve"}` | `RESERVED` | 中止 |
| 5 | 期限までの残り時間を確認 | 45分以上(Workerは15分未満なら開始しない) | 中止。期限は延長しない |
| 6 | Workerスタック作成(スタックポリシー適用) | インスタンスが `running` | スタック削除、記録 |
| 7 | 監視のみ。介入しない | `EVIDENCE_COMMITTED` → 自己シャットダウン → `terminated` | 層2が期限で終了させる |
| 8 | 終了確認 | Describeで `terminated`、制御状態 `TERMINATED_VERIFIED`、ボリューム・ENIなし | `TERMINATE_UNCERTAIN` は有人対応 |
| 9 | 証拠の検証 | §6 | 失敗として保存 |
| 10 | Workerスタック削除 → ガードは `GuardEndAt` 以降に削除 | 残余資源を棚卸し | — |

失敗した試行をやり直す場合は、新しい `PilotRunId` で新しいガード面と新しいインスタンスを作る(同じインスタンスは再起動しない)。試行回数の上限は別承認事項。

## 6. 証拠の検証(終了後、読取りのみ)

1. `runs/<PilotRunId>/run-manifest.json` を取得し、SHA-256を計算する。
2. `run-manifest.sig.json` の `signed_sha256` と一致することを確認する。`status` が `SIGNED` ならKMS Verify(`src/aws_c/signer.verify_with_kms`)、`UNSIGNED` なら未署名として扱う。
3. マニフェストの各オブジェクトについて、S3のSHA-256チェックサム属性と本体の再ハッシュが `sha256` と一致することを確認する。
4. `s1/` 以下をローカルへ取得し、既存の `plan_recovery`(`src/aws_c/evidence.verify_local`)で整合を再確認する。
5. `claims` は固定で `quality=UNKNOWN`、`profile_trust=PROFILE_UNATTESTED`、`target_scope=CONTROLLED_FIXTURE_ONLY`。署名やPASSがあっても品質PASSとは扱わない。

## 7. LIVE隔離の負例(EC2上で再実測する項目)

既存ハーネス(`tests/runtime/validate.py`)がそのまま測るもの: UID別のTCP/UDP/DNS/IPv6直通拒否、Proxy停止時のfail-closed、sandbox・capability・seccomp・cgroupの観測、DROPカウンタの増加。これらのLocal(Windows/WSL2)でのPASSはAWSのPASSではない。

EC2で追加して確認する項目(手順は未実装・計画のみ):

| 項目 | 期待 | 現状 |
|---|---|---|
| 実IMDS(169.254.169.254)へのBrowser UIDからの到達 | 到達0。Localでは同アドレスの「モデル」だった | 計画のみ |
| IMDSv2 hop制限1でのコンテナからの資格情報取得 | 取得不可 | 計画のみ |
| VPC DNS(.2リゾルバ)へのBrowser UIDからの問合せ | 到達0 | 計画のみ |
| IPv6外向き | SGにIPv6許可なし＋iptablesでDROP | 計画のみ |
| SG外向きが443のみであること | 80/その他は不通 | 計画のみ |
| ホスト(Trusted Worker)の外向き先 | S3/DynamoDB/ECR/KMSのみを使用。ただしSGはホスト名で絞れない | 既知の限界 |

## 8. 失敗時の証拠保全と復旧

- 隔離失敗・ハーネス例外・検証不整合のいずれでも、取得できたファイルとレポートはそのままwrite-onceで公開する。`run-manifest.json` に `local_verification` と未公開オブジェクトが記録される。
- マニフェストが無いrunは「証拠未確定」。後から補完・上書きしない。
- 公開済みオブジェクトと異なる内容での再公開は `CONFLICT` になり、置換されない。
- インスタンスは復旧しない。原因調査は公開済み証拠とCloudTrailで行い、再試行は新しいrunで行う。
- バケットとテーブルはRetain。削除は別承認。

## 9. 未確認事項(LIVEまたは公式確認が必要)

- `s3:if-none-match` 条件キーによる無条件PUTの拒否、`ec2:ResourceTag/...` 条件つきTerminateの実効。
- Scheduler `at()` 式と `EndDate` の受理形式。
- CloudFormationがインスタンスを作成した時点でタグが付いているか(Watchdogの発見性)。
- Docker bridgeとIMDS hop制限、VPC DNSの到達性。
- マシンイメージの作成方法、ルートデバイス名、T3のクレジット設定。
- Linuxホスト上での既存ハーネスの動作(`LinuxDockerLauncher` は実Dockerでは未実行)。
- KMS署名の費用と必要性(既定は無効)。
- 実サイト(本人所有)撮影は未実装。別Gate。

## 10. マシンイメージ作成手順（オフライン作成済み／未実行）

AWS-C LIVE承認にはbuilder 1回＋fixture worker 1回を別々に計上する。再試行と本人サイト撮影は残枠を明記して承認する。以下は手順であり、現在は実行しない。

1. us-east-1、Ubuntu 24.04 LTS amd64の公式AMIを選び、所有者・AMI ID・RootDeviceNameを保存。t3.small、gp3 30GB、CPUCredits=standard、IMDSv2必須・hop=1、SSH受信なしのbuilderを1台作成。作成時からOS shutdown=terminate、EBS DeleteOnTermination=trueとし、独立した60分のTerminate手段を先に用意する。
2. 承認済みのビルド用接続で `apt-get update`、`apt-get install -y docker.io python3 python3-boto3`、`systemctl enable --now docker` を実行。外部取得はこのbuilderだけで行い、worker起動時には行わない。作業に使う一時的な管理経路と権限もAWS-C承認に含める。
3. `python3 --version`、`python3 -c 'import boto3; print(boto3.__version__)'`、`docker version`、`docker info`、`dpkg-query -W` を保存。Python 3.11以上、Docker cgroup v2、ローカルunix socketを確認。パッケージの正確な版と元AMI IDを記録し、同じAMIを使うことでworker環境を固定する。リポジトリを再取得しただけのビルドはbit単位再現とは主張しない。
4. 既存 `runtime/docker/Dockerfile` からランタイムを構築、ECRへ登録してdigestとビルドログを保存する。Playwrightとseccompは既存資産を使用する。ホスト側ソースは既存worker-bundleで配る。
5. 汎用AMIにrun固有UserData・認証ファイル・Docker registryログイン・証拠を残さない。`cloud-init clean --logs` 後、AMIのCreateImageを実行してavailableを確認。再起動を伴う既定CreateImageは使わず、NoRebootとファイルシステムsyncを使用し、作成後のworkerで検証する。AMI ID・snapshot ID・元AMI・パッケージ一覧・bundle SHA・ECR digestを同じ実行索引へ記録。
6. builderをTerminateし、EBS削除を確認。AMI snapshot/ECRはworker終了後も費用が残る。保持期限（提案7日）と登録解除・snapshot削除をAWS-C承認に含める。
7. worker起動には得られたAMI IDと正しいRootDeviceNameを指定し、既存Runbook §5を実行。実IMDS/VPC DNSの隔離実測がPASSするまで本人サイト撮影へ進まない。既存ハーネスの169.254.169.254はloopbackモデルであり、実IMDSの証拠には使わない。

未完了: AWS固有の実宛先隔離プローブ、本人サイト撮影経路、AMI作成・Linux実行・停止・費用の実測。AWS-C NO-GO / C-02 DEFERRED・OPENを維持。
