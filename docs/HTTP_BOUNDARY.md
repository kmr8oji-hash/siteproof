# HTTP監視の通信境界（Docker隔離・1回実行型）

2026-11-25（Sprint 03）。対象：`src/noxiworks/http_isolation.py`・`http_authority.py`・`http_monitor.py`、`src/isolation/http_*_worker.py`・`http_exchange.py`、`tools/http_grant.py`。
参考：`18_ADR_MONITOR_OWNERSHIP`・`19_ADR_PROVIDER_EGRESS_AUDIT`（どちらも DRAFT / NOT ADOPTED）。

> **外部通信は無効のままです（`HTTP_EXTERNAL_ENABLED = False`）。** 2026-11-26、外部ネットワークのない隔離fixtureで **18件すべてPASS（GREEN）**（`.local/http-iso-run-04`）。**M3：本人管理サイト（workers.dev）で限定試験4回を実測（2026-11-26・すべて HTTP 200・隔離違反なし。RELEASE_CANDIDATE.md 5.2）。**
> 画像撮影の隔離（S2-B）の実測結果は、HTTP監視の境界の証拠ではありません。部品は同じでも、組み合わせは別に測ります。

Sprint 02 の「監視付き子プロセスだけで動かす方式」は採用せず、コードから外しました。実サイトへの要求は、下の隔離実行だけが行えます。

## 1. 構成（検査1回ごとに作り、終わったら消す。常駐しない・Chromiumは起動しない）

| 部品 | 実体 | 権限 |
|---|---|---|
| ネットワーク空間の保持 | 眠るだけのコンテナ（180秒で自分から終わる） | UID 1001・権限なし |
| OSの規則 | `tests/runtime/netpolicy_hardened.py`（**画像撮影と同じ・無変更**）。IPv4/IPv6とも既定で破棄 | 短時間だけ NET_ADMIN |
| Grant Broker | `tests/runtime/egress_broker.py`（同上）。唯一の名前解決・唯一のアドレス許可（1件・IPv4・443・30秒） | NET_ADMINのみ |
| Reaper | `tests/runtime/egress_reaper.py`（同上）。期限・ホスト側の停止・命令で、独立に通信窓を閉じる | NET_ADMINのみ |
| CONNECT Proxy | `http_proxy_worker.py`：既存の ConnectTransport（無変更）＋Broker経由の名前解決。許可ホスト1件 | UID 1001・権限なし |
| HTTP Worker | `http_probe_worker.py`：Proxy経由でTLSを端から端まで張り、先頭行だけ読む | UID 1000・権限なし |

Workerに渡すもの：必要なPythonファイル14個（読み取り専用）と名前解決の設定ファイルだけ。**リポジトリ・データフォルダ・許可・鍵・Docker socketは渡しません**（Workerの報告とDockerの記録の両方で毎回確認）。

## 2. 1回の流れ

1. 停止スイッチ → 許可の事前確認 → Dockerが動いているか・固定イメージがあるか（**起動・取得・ビルドはしない**。なければ検査せず、回数も消費しない）
2. すべてを**閉じた状態**で用意し、OSの規則が想定どおりかを確認（違えば中止）
3. 許可v2を新しく検証し、台帳に1回分を記録（ここまでに失敗したら消費しない）
4. Reaper → 通信窓 → 貸出 → 要求1回 → Proxyの記録・Brokerの状態・OSの破棄数を採取
5. 窓を閉じ、規則が最初と完全に一致することを確認 → 自分が作ったコンテナとネットワークだけを削除
6. 記録を突き合わせて判定。**想定と1つでも違えば「観測なし」とし、監視を停止**（`ISOLATION_VIOLATION`）。記録は `http-audit.jsonl`

## 3. 何が何で強制されるか

| 条件 | ネットワーク／OSで強制 | アプリケーションで固定 |
|---|---|---|
| 直接のTCP・UDP・DNS・IPv6 | ✓ 既定で破棄（Workerが届くのはProxyの1ポートだけ） | ✓ ProcessGuard（第二の層） |
| 名前解決 | ✓ Brokerだけ（Worker・Proxyはできない） | ✓ 回答の全件検査 |
| 接続先IP・ポート | ✓ Brokerが開けた /32:443 だけ | ✓ 接続後の照合 |
| ホスト | Proxyの許可リスト1件＋Brokerの登録1件 | ✓ 許可・登録内容 |
| **パス** | **✗ 強制できない**（CONNECT Proxyは暗号化された中身を見られない） | ✓ 署名つき許可とコードで固定 |
| TLS証明書・ホスト名 | — | ✓ Workerが端から端まで検証 |
| リダイレクト | 別ホストなら接続できない | ✓ 追従しない |
| 期間・間隔・回数・所有権 | — | ✓ 許可v2・台帳 |
| 時間 | ✓ Reaper 40秒・許可30秒・コンテナ180秒 | ✓ 全体8秒 |
| 通信量 | ✓ Proxyの上限 512KiB・接続4 | ✓ 先頭16KiBまで |
| Proxy・Brokerの停止 | ✓ 出口がなくなる（fail closed） | ✓ 判定不能として扱う |

## 4. 状態

| 項目 | 状態 |
|---|---|
| 手順の順序・異常時の停止・判定・回数の扱い | オフライン検証済み（模擬Docker。`tests/ui/test_http_isolation.py`） |
| 「閉じた規則」の判定 | 画像撮影で保存済みの実測スナップショット4件で、閉/開を正しく区別することを確認（再実行はしていない） |
| コンテナの起動・OSの規則・実TLS・後片付け | 隔離fixture（`--internal`・実サイトなし）で**実測済み**。実サイトでも本人管理サイト（workers.dev）で限定試験4回を実測（2026-11-26・すべて HTTP 200・隔離違反なし。RELEASE_CANDIDATE.md 5.2） |
| 固定fixtureでの正例・負例（18件） | **18/18 PASS**（2026-11-26、`.local/http-iso-run-04`、固定イメージ `sha256:9c88112b…`）。コンテナ・ネットワークの残りなし |
| 実サイト1件での限定試験（M3） | **PASS**（本人管理サイト（workers.dev）で限定試験4回を実測（2026-11-26・すべて HTTP 200・隔離違反なし。RELEASE_CANDIDATE.md 5.2）。試験後にスイッチを `False` に戻した） |

実測の経緯：run-02で `nothing_listening` が FAIL（許可したIPへの接続の時間切れを、ProxyのCONNECTION_TIMEOUTとして判定不能にしていた）。`judge()` を、経路全体が正常（Brokerが許可・OSの許可規則あり・Proxyがその1つのIPに1回だけ接続して失敗・信頼側の遮断なし）なときだけ `FAIL / CONNECT_TIMEOUT`（拒否・到達不能は `CONNECT_FAILED`）とし、Broker・Proxy・規則の異常は従来どおり判定不能にした。あわせてProxyの接続期限を5秒にし、Workerの8秒より先にProxyが決めて台帳に残すようにした。run-03では `server_error` が1回だけ TLS_FAILED になった（単独の再実行と run-04 ではPASS。原因はUNKNOWN。以後はWorkerがTLSの失敗の種類を、fixtureの相手が自分側のエラーを記録する）。

## 5. 実測に必要なもの（不足なし・取得不要）

既存の固定イメージ（`sha256:9c88112b…`、画像撮影と同じ）だけで実測できます。追加のビルド・取得は不要です。python・openssl・iptables・iproute2・CA証明書は、このイメージで以前使われたものです（HTTP用としては未確認）。`nft`・`ipset` は使いません。

### M2：隔離fixtureの実測（実施済み・18/18 PASS）
```
py -3.15 -B -m tests.runtime.validate_http_iso --evidence .local\http-iso-run-01
```
外部ネットワークなし（`--internal`）。正例、リダイレクト、503、長すぎる応答、少しずつ送る相手、応答しない相手、証明書の不一致・不信頼、私設/メタデータ/ループバック/混在/IPv6だけの回答、解決不能、接続拒否、Proxy停止、Broker停止、許可中の直接接続（TCP・UDP・DNS・別IP・別ポート・私設・Broker・IPv6）。
1件でも想定と違えば、その時点で停止（RED）。実行しなかったものは `NOT_RUN` のまま（合格にしない）。作ったコンテナ・ネットワークだけを削除し、既存のイメージ・volumeには触れません。目安20〜30分。

### M3：本人管理サイト1つへの限定試験（別の承認）
USERが `tools/http_grant.py --trial --hours 2 --max-requests 5` に署名 → `HTTP_EXTERNAL_ENABLED = True` → 手動検査（最大5回、60秒以内の再実行が通信なしで拒否されることを含む） → 期限切れ後に通信しないことを確認 → `False` に戻す。
中止条件：`ISOLATION_VIOLATION`、台帳と `http-audit.jsonl` の回数の不一致、片付け残り。

### M4：常時監視
M3の記録を確認後、`MONITOR` の許可に署名。**Docker Desktopを起動しておく必要があります**（HTTP監視のために自動で起動することはありません。動いていない間は「検査していない」と表示し、障害とは扱いません）。

## 6. 残る制限

- 1回あたりの所要時間：fixtureで約20秒（コンテナの準備・後片付けを含む。通信の窓は2〜10秒）。実サイトでは約13〜20秒（検査の開始から記録まで）。同時に3件まで。多数のページを5分間隔で監視すると間に合わないことがあります（間に合わない分は観測なしとして表示）。
- 名前解決そのものの真正性は、Docker Desktopの設定に従います。
- このPCの時計とローカルファイルを信頼します（PCの利用者＝サイトの所有者が前提）。
- 管理者権限を持つローカルの攻撃者、Docker Desktop・カーネルの欠陥に対する保護ではありません。正式な LOCAL-ISOLATION の合格を意味しません。
- ホストの強制終了時：Reaperが窓を閉じ、コンテナは180秒以内に終わりますが、空のネットワークやコンテナの残骸が残ることがあります（次の実行には影響しません）。
