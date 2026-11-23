# Phase 0: 資産保全の状況と承認待ち事項

2026-11-11 のStart Gate(READ-ONLY)で確認した内容。今回の作業は新規worktree内だけで行い、main、既存worktree、Obsidian正本、証拠原本、VMには書き込んでいない。

## Start Gateの確認結果

| 項目 | 結果 |
|---|---|
| main | `b52bd38e2868e5371b3005f8cd1d23b2380bec41`、working tree・indexともclean |
| 既存worktree | 33本(mainを含む)。`siteproof/aws-portfolio*` の既存ブランチなし |
| 新規worktree | `<worktrees>\siteproof-aws-portfolio-fable-01`、ブランチ `siteproof/aws-portfolio-fable-01`(`b52bd38` から作成) |
| G1資産 | worktree `siteproof-g1-provider-01` に未追跡24ファイル、テスト107件(静的計数)。存在を確認 |
| Obsidian正本 | SiteProof配下で8件modified・7件untracked(未commit) |
| VM | 最終報告は11-09 15:17の `FINAL_SAFE_STATE.json`(両VM Off、NIC切断、watchdog Disabled)。**今回は状態を再確認していない=現在の状態はUNKNOWN**。VMは起動していない |
| Python | 3.15.1(`py -3.15`)。既定の `python` は3.10.6で既存コードには不適 |

## 既存資産の扱い(今回)

| 資産 | 扱い | 根拠 |
|---|---|---|
| `src/**` `tests/**` `web/**` `runtime/**` `infra/public_web/**` の既存ファイル | **1ファイルも変更していない** | `tests/aws_c/test_worker_entry.py::test_existing_launcher_file_is_unmodified` が `git status` で確認。新規ファイルの追加のみ |
| 既存DB・証拠形式・manifest形式 | 変更なし。AWS-C用の `run-manifest.json` は別ファイルとして追加 | `src/aws_c/evidence.py` |
| 既存テスト | 削除・無効化・スキップ指定なし。1,396件を実行 | `tools/run_offline_tests.py` |
| Kuma / Lighthouse / Local HOME | 追加開発なし(一時保留)。資産は削除していない | — |

## 消失リスクと承認待ちの保全操作

いずれも今回は**実行していない**。対象と方法を示す。

| # | 対象 | リスク | 提案する方法 | 必要な承認 |
|---|---|---|---|---|
| P1 | G1未追跡24ファイル(`siteproof-g1-provider-01` worktree) | 未追跡のためworktree削除や誤操作で消える。現状の保護は `handoffs` 内のpatchとSHA記録のみ | 当該worktreeの既存ブランチ `siteproof/g1-provider-01` へ保全commit(mainへは入れない) | 既存worktreeへのcommit |
| P2 | 今回の新規ファイル(このworktreeの未追跡分) | 同上。commitは今回禁止されている | ブランチ `siteproof/aws-portfolio-fable-01` へのcommit | このworktreeでのcommit |
| P3 | M5証拠 `<repo>\.local\`(2,199ファイル、約24.8MB) | git管理外の単一コピー | 読取専用の別ドライブへコピーし、SHA-256台帳を作成 | 証拠のコピー作成 |
| P4 | M2/M3原証拠(Docker named volume) | Docker Desktopの再初期化で消える。現存は未確認 | `docker cp` 相当でエクスポートしハッシュ照合 | Docker操作 |
| P5 | Obsidian正本の未commit分(15件) | 未commit。11-07〜09のG1-B作業と今回の作業が未反映 | Commander裁定後に限定同期・Vault commit | 正本への書込み |
| P6 | 開発Gitにリモートが無い | ローカルディスク障害で全履歴を失う | バックアップ先(bare repoまたは非公開リモート)の設定 | push先の決定 |
| P7 | `handoffs\SiteProof\g1-b-20261107\**\private\`(SSH鍵、DPAPI資格情報、約90GBのディスクイメージ) | 平文相当で残存。保持期限が未定 | 保持期限を決め、不要分は削除。必要分は暗号化保管 | 削除・暗号化 |
| P8 | VM 2台と内部スイッチ(`<vm-dir>\`) | 状態が未確認のまま残存 | 管理者権限で状態を読み取り確認。保持か削除かを決定 | UAC昇格、VM操作 |
| P9 | 既存の不整合テスト1件(`tests/bff/test_runtime_view.py`) | 基準実行が常に1 FAILになる | テストの期待値を `/local/workspace.js` へ更新(M5の意図に合わせる)。製品コードは変更しない | 既存テストの修正 |

## 今回コピーしなかったもの

秘密鍵、認証情報、`private` ディレクトリ、VMディスク、実DB、アカウントIDは、新規worktreeにも公開用文書にも含めていない。`tools/build_bundles.py` は許可リスト方式で、`.local` `private` `secrets`、`.sqlite` `.pem` `.key` `.log` を拒否する(テストあり)。
