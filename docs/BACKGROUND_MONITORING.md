# アプリを閉じている間の監視（OSのスケジューラー）

SiteProofの自動監視は、次の2通りで動きます。どちらも同じ処理（`src/noxiworks/site_monitor.py` の `Monitor.run_if_due`）を使います。

| 状態 | 動き |
|---|---|
| アプリ起動中 | アプリのバックグラウンド処理が数秒ごとに予定を確認し、予定時刻になったら検査します |
| アプリ終了中 | OSのスケジューラーから、次のコマンドを定期的に（例：15分ごと）実行します。予定時刻を過ぎていれば1回だけ検査し、まだなら何もしません |

```
py -3.15 -B -m src.noxiworks.site_monitor --data "%LOCALAPPDATA%\SiteProof"
```

- 同時に2つの検査が動かないよう、ロックファイル（`monitor.lock`）で排他します。アプリ起動中にOS側のコマンドが動いても、二重には検査しません。
- 検査結果は同じデータフォルダに保存されます。次にアプリを開くと（起動中なら数秒以内に）画面に反映されます。
- 監視を停止中（画面の「監視を停止」）の場合、コマンドは何もしません。
- HTTP監視（サイトの死活。[HTTP_MONITORING.md](HTTP_MONITORING.md)）は、**別のタスク**（5分ごと・`http-tick`）で動きます。画像の長い撮影に左右されず、ブラウザは使いません。各検査は隔離コンテナで1回ずつ行うため、Docker Desktopが起動しているときだけ検査します（HTTP監視のためにDockerを起動することはなく、起動していないと検査せず「未検査」と表示します）。外部通信は、承認が済むまで無効です。タスクはサイトごと・チャンネルごとで、サイトの全ページを確認します。

| | 画像監視のタスク | HTTP監視のタスク |
|---|---|---|
| 名前 | `SiteProof-Image-<site id>-<h>` | `SiteProof-Http-<site id>-<h>` |
| 間隔・動作 | 15分ごと・`tick` | 5分ごと・`http-tick` |
| Docker・ブラウザ | 予定の撮影があるときだけ | ブラウザは使わない・Docker Desktopが起動済みのときだけ検査（起動はしない） |
| ログ | `background\<site id>-image.log` | `background\<site id>-http.log` |

`<h>` はデータフォルダのパスから作る8文字です。データフォルダ・サイト・種類のどれかが違えば名前も違い、衝突しません。登録・解除はサイトごと・種類ごとに別々で、解除は名前の一致するタスクだけを消します。
旧い名前 `SiteProof-Monitor-<site id>` は、もう作りません（このPCでは解除済みで、追加の作業はありません。残っている場合は `remove --legacy` を付けたときだけ解除します）。
- **SiteProofはOSのスケジューラーへの登録を自動では行いません。** 登録するかどうかは利用者が決めます。

## 登録例（利用者が自分で実行するもの・SiteProofは実行しません）

### Windows（タスク スケジューラ）

通常は画面から：HOMEの「実サイト監視の準備」で **アプリを閉じても監視する**（解除は同じ場所の **解除する**）。
中身は `tools/background_monitor.py install` / `remove`（`--channel image|http`）です。タスクは `<データ>\background\<site id>-image.cmd`（HTTPは `-http.cmd`）を実行します。
このファイルは、**`install` を実行したそのPython**（`sys.executable`。仮想環境ならその環境。Pythonのバージョンは固定しません）で動きます。同じ場所に `pythonw.exe` があればそれを使い（ウィンドウが出ません）、なければ `python.exe` を使います（15分ごとにコンソールが開きます）。PATHにある別のPythonへは切り替えません。実行ファイルが見つからないときは、タスクを登録せずに中止します。パスは引用符で囲み、`%` は `%%` にして書くため、空白があっても動きます。日本語を含むパスは、UTF-8と `chcp 65001` で書きます（生成したファイルを `cmd.exe` で実行して確認。タスク スケジューラからの実行は未検証）。引用符や制御文字を含むパスは、登録せずに中止します。**Pythonを入れ替えたり仮想環境を作り直したりしたら、`install` をやり直してください。**
※Windowsのタスク スケジューラでの実際の実行は、この変更後はまだ確認していません（オフラインのテストだけです）。
`tick` は予定時刻を過ぎているときだけ1回検査し、実サイト監視の設定があるのにDocker Desktopが応答しなければ、起動して最大3分待ちます。

```powershell
py -3.15 -B tools/background_monitor.py install --data <データ> --site <site id> --channel http --dry-run   # 登録するコマンドの確認だけ（登録しない）
py -3.15 -B tools/background_monitor.py status  --data <データ> --site <site id>                         # 登録の有無とログの末尾（両方の種類）
```

### macOS（launchd）

`~/Library/LaunchAgents/local.siteproof.monitor.plist`：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>local.siteproof.monitor</string>
  <key>WorkingDirectory</key><string>/path/to/siteproof</string>
  <key>ProgramArguments</key><array>
    <string>/usr/bin/env</string><string>python3</string><string>-B</string><string>-m</string><string>src.noxiworks.site_monitor</string>
    <string>--data</string><string>/Users/YOU/.local/share/siteproof</string>
  </array>
  <key>StartInterval</key><integer>900</integer>
</dict></plist>
```

`launchctl load ~/Library/LaunchAgents/local.siteproof.monitor.plist` で有効にし、`launchctl unload …` で止めます。

## 実環境での確認手順（Windows・USERの承認後にまとめて実施）

準備済みのもの：GUIのボタン（登録・解除・状態表示）、`background_monitor.py`（install / remove / status / tick、Docker起動待ち）、
同時実行の防止（`monitor.lock`）、代役による確認（`tests/ui/test_setup_monitoring.py`・`tests/ui/test_e2e_saved_data.py`・GUIリハーサル）。
**まだ行っていないこと：実際のタスク登録、Docker Desktopの起動、タスクからの実サイト撮影。** 次の操作には、それぞれUSERの承認が必要です。

| # | 確認すること | 操作 | 期待する結果 |
|---|---|---|---|
| 0 | 前提 | 有効な監視許可があるデータフォルダ（HOMEが「実サイト監視中」）。Windowsにサインインしたまま | — |
| 1 | タスク登録 | HOMEで **アプリを閉じても監視する** | 表示が「アプリを閉じている間の監視：有効」。`tools/background_monitor.py status` で存在 |
| 2 | アプリ終了中の監視 | アプリを閉じ、HOMEの「次回検査予定」を過ぎるまで待つ（試験時は検査間隔を15分に） | `<site id>-image.log` に予定時刻後の1行。`monitor-log.jsonl` に `trigger: SCHEDULE` の結果。次にアプリを開くと画面に反映 |
| 3 | 予定前は何もしない | 予定前の `tick` | `<site id>-image.log` に何も増えない（予定前は出力しない）・撮影回数が増えない |
| 4 | Docker起動 | Docker Desktopを終了した状態で、予定時刻を過ぎる | `tick` がDocker Desktopを起動し、応答を待ってから検査（3分で応答しなければ、その回は記録だけ） |
| 5 | アプリとの同時実行防止 | アプリを開いたまま予定時刻を迎える | 検査は1回だけ（`monitor-log.jsonl` に1行、撮影回数+1）。もう一方は「busy」または「not due」 |
| 6 | タスク解除 | HOMEで **解除する** | 表示が「無効」。`schtasks /Query` で見つからない。アプリを開いている間の監視は続く |

注意：
- 2・4・5 は実サイトへのアクセス（撮影）とDockerの実行を伴います。許可の期間・回数の範囲内で行います。
- Docker Desktopを起動していない状態で撮影が始まると、その回は失敗として撮影回数を1回消費します（画面の準備チェックは、エンジンが応答しないとき撮影しません）。

## 注意

- macOSの例は動作確認をしていません。Windowsのタスク登録も、実環境ではまだ行っていません（上の手順で確認します）。コマンド自体（`site_monitor --data …`）は、アプリ終了中に予定時刻を過ぎた検査を1回実行し、予定前は何もしないことを確認済みです。
- 実サイト監視の設定（署名付きの監視許可）があるデータフォルダでは、タスクからの検査も実サイトを撮影します。
- 検査が異常終了してロックファイルが残った場合、15分経つと次の検査が引き継ぎます。
