# SiteProof 公開静的フロントエンド — オフライン候補

**OFFLINE CANDIDATE / AWS LIVE NO-GO / AWS SERVICE VALIDATION NOT RUN**

CloudFormation JSONと静的検査の候補です。AWS公式仕様との最終照合、AWS template validation、認証、デプロイ、配信・請求・Visualの実測は行っていません。静的テストPASSは、AWSが受理することや安全な実運用の証明ではありません。

## 範囲

CloudFront + private S3による静的フロントエンドだけを扱います。既存HOMEの合成Jobデモ、未認証JSONレポートViewer、別Laneのローカル画像比較ページを将来配信するための候補です。アップロードAPI、撮影worker、ジョブ実行、比較Backendは作りません。

将来のARCH-LEAN Pilot（Lambda + DynamoDB + EC2 + S3等）とは別です。Pilot正式採用・構築・接続を意味しません。初回EC2起動1回、再armなし、AWS C-02 DEFERRED / OPENを維持します。

## 候補の構成

| Resource | 用途と境界 |
|---|---|
| AssetsBucket | 自動命名、Block Public Access全4項目、BucketOwnerEnforced、AES256、versioning。削除・置換時Retain |
| OriginAccess | S3用OAC、always / sigv4。OAI・website endpointを使わない |
| WebCachePolicy | TTL 0/60/300秒、cookie/header/queryの転送なし、圧縮用encodingだけ |
| WebHeadersPolicy | HTTPS/HSTS、nosniff、DENY、no-referrer、CSP、Permissions-Policy、same-origin resource policy |
| Distribution | S3 regional endpoint、origin prefixなし、GET/HEADのみ、HTTP→HTTPS、default CloudFront certificate |
| AssetsPolicy | 当該account/distributionのCloudFrontだけに指定6キーのGetObjectを許可。非TLSを明示拒否 |
| RootRedirect | CloudFront Function候補。viewer-requestの`/`だけを固定302で`/home/index.html`へ移動。他URIは変更しない |

`PublishEnabled`の初期値は`false`です。`true`は設定値でありUSER承認ではありません。disabledでも作成・保管に伴う費用をゼロと保証しません。追加のIAM user/role、EC2、Lambda、DynamoDB、API、DNS、ACM、WAF、ログ配送資源、予算通知資源は作りません。

商用AWS partition向けの候補です。Region/accountは未決定。CloudFrontはglobal、S3は選択Regionです。他partition、実在性・quota・OAC/証明書・policy伝播の確認はUNKNOWNです。

## 公開ファイルの厳格な切り出し

`package_public.py`は、指定した`web`ディレクトリから下表の6ファイルだけを、バイト列を変えず新規ローカル出力へ抽出します。アップロードは行いません。**repository全体のsyncは禁止**です。

| Source（統合・レビュー後のファイル） | S3 key |
|---|---|
| web/home/index.html | home/index.html |
| web/home/styles.css | home/styles.css |
| web/home/app.js | home/app.js |
| web/compare/index.html | compare/index.html |
| web/compare/styles.css | compare/styles.css |
| web/compare/app.js | compare/app.js |

DefaultRootObject候補は`home/index.html`です。ただしこれはブラウザのURLを変えません。`/`でHOMEを返すだけでは`styles.css`が`/styles.css`へ解決され、許可6キーに存在しません。そこで7番目の資源RootRedirectを追加し、`/`を`/home/index.html`へ固定302（no-store）で移動する候補にしています。host/queryを転記せず、任意のリダイレクト先を受け付けません。移動後のCSS/JSと`../compare/index.html`、Compareの`../home/index.html`は6キー内へ解決されます。ディレクトリindex推測・SPA fallback・Backend接続はありません。

この根本URL問題はURL解決の静的負例と合成イベントに対するNode実行で検査します。AWS公式仕様の最終照合・関数の実AWS実行・関連付け順序・HTTPS/headers適用・実Browser表示はUNKNOWNです。**AWS公開可能と認定しません**。CloudFront FunctionはLambdaやARCH-LEAN Pilotではありません。

## パッケージ作成とUSER審査

統合後の作業ディレクトリで、例として`py -3.15 -B infra/public_web/package_public.py web C:\review\siteproof-new-release`を実行します。出力先の親は存在する通常ディレクトリ、出力先自体は**未存在**である必要があります。既存の空ディレクトリも拒否し、既存出力の上書き・削除・再利用はしません。

- `payload/home/`と`payload/compare/`だけが将来のアップロード対象（計6ファイル）です。
- `review_manifest.json`はpayloadの外に置くUSER審査専用ファイルです。公開しません。各source/key、SHA-256、byte数、Content-Type、template SHA-256を確認できます。時刻や絶対パスを含めず決定的に生成します。署名・発行者認証・USER承認の代替ではありません。
- 欠落・余分なファイル/ディレクトリ（隠しファイル含む）、symlink/reparse point（祖先も含む）、hardlink、パストラバーサル、異常サイズ/非UTF-8/NUL、既知の鍵形式を拒否します。ファイルidentity/size/mtime、path ctime、読込み・書込み後のreadbackとSHA整合を確認します。
- HTMLはCSS/JSと正式な2ページの相対参照だけ、CSSは追加依存なし、JSは明示した通信/追加依存パターンなしを静的検査します。HTMLの重複属性も拒否します。汎用HTML/JSセキュリティ解析器ではありません。
- 一般の機密情報が6ファイルの本文に書き込まれていないことを静的パターン検査だけで証明できません。USERが公開6ファイルの全内容・hash・source commit・MIMEとtemplateを審査します。未知のSecretsやユーザー情報を公開してよいという意味ではありません。
- 失敗時は部分出力を残して終了コード1にします。完了済みとして使わず、無断修復・自動削除しません。`verify_package()`による再読取りも別途利用できます。hashを攻撃者が同時に書き換えたパッケージの真正性は証明しません。
- 制御された静止中のローカルfilesystemを前提とします。悪意ある別プロセスによる祖先ディレクトリの同時置換を封じるOS sandboxではありません。共有書込み先・UNC・不明なマウントは使いません。

Lane Aはbase時点の6ファイルを検査し、Lane Bの未統合ファイルのhashを推測しません。通常作成は双方向リンクを必須にします。検査用の`--pre-integration`だけはリンク未追加を許し、manifestの`navigation_complete=false`を明示します。これは公開準備完了ではありません。**統合後の最終6ファイルで通常モードを再実行し、USER審査を経ることが必須**です。

Bucket PolicyのAllowはこの6キーだけです。別prefixや未列挙キーをCloudFrontへ公開しません。ただし承認キーの中身が機密なら漏れるため、キー制限だけで内容審査を代替できません。各ファイルのsource commit、SHA-256、byte数、MIME、公開可否をUSERが承認する必要があります。

**公開禁止:** `.git`、`.claude`、`.codex`、資格情報・Secrets・環境設定、IaC/内部文書、Python source/tests、fixtures、SQLite DB/WAL/SHM、Snapshot、Manifest、実証拠、ユーザー選択JSON/画像、個人情報、Obsidian、ローカルパス情報。画像は将来もブラウザ内処理で、配信先へ保存・送信しません。

S3直接公開、ACL public-read、website hosting、CORSは構成しません。ローカルファイルをブラウザ内で扱うためCORSの追加は不要です。CSPのblob/data画像許可はローカル画像用であり、外部画像・Backend通信の許可ではありません。ページ側meta CSPとHTTP CSPは両方適用されるため、実Browserでの整合確認は後続Gateです。

## オフライン検査

`py -3.15 -B -m unittest discover -s tests/aws_public -p "test_*.py"`

Python標準ライブラリでJSON構文・重複キー、参照先、リソース範囲、S3/OAC/policy/HTTPS/header/cache境界を検査します。安全設定の改変を拒否する負例も含みます。AWS仕様全体のvalidatorやIAM policy simulatorではありません。AWS CLI/API、CloudFormation validation/deploy、CDK synthを実行済みとは扱いません。

## 状態の出所

開発GitのbaseとUSERの今回指示を作業基準とします。Obsidian正本のHOME Case Study、Commander State、Current TaskはREAD-ONLYで確認しました。正本には過去時点の開発HEAD・タスクが含まれており、今回のGit状態と同一の最新版とは扱いません。添付・転送スナップショットを正本へ昇格させず、正本を今回の成果で更新しません。

運用・費用は[security_and_cost.md](security_and_cost.md)、実AWS前の承認条件は[deploy_gate.md](deploy_gate.md)を参照してください。
