# HANDOFF / Checkpoint — SiteProof AWS Portfolio(オフライン)

**Worktree:** `<worktrees>\siteproof-aws-portfolio-fable-01`
**Branch:** `siteproof/aws-portfolio-fable-01`(base `b52bd38`。commitは0件。成果はすべて未追跡ファイル)
**状態:** オフライン実装・テスト・文書化が完了。**AWS LIVEは未実施(AWS-B / AWS-C LIVE NO-GO、C-02 DEFERRED / OPEN)。**
**main:** `b52bd38`、clean(変更なし)。

## 再開手順

1. worktreeへ移動し、`git status --short` が未追跡パス(下記)だけを示すことを確認する。既存ファイルの変更(` M`)があれば想定外。
2. 全テストを反復しない。FAST TRACK限定16/16 PASSは `TEST_RESULTS.md`、配備bundleは `.local/aws-portfolio-01/fast-track-01/bundles/`。既知の既存FAIL 1件は修正対象外。
3. `docs/aws_portfolio/README.md` から各文書へ進む。

## 完了チェックリスト

- [x] Phase 0: Start Gate、基準実行(1,396実行 / 1,395 PASS / 1 既存FAIL)、保全リスクの整理
- [x] Phase 1: `infra/ops_guard`、`tests/aws_guard`(36)、Runbook
- [x] Phase 2: `src/aws_b`、`infra/aws_b`、`tests/aws_b`(110)、Runbook
- [x] Phase 3: `src/aws_c`、`infra/aws_c`、`tests/aws_c`(161)、バンドル作成ツール、Runbook
- [x] Phase 4: 構成図、費用、受入基準、証拠索引、保全、面接ポイント、未解決事項、テスト結果、README
- [x] 最終回帰: 1,703実行 / 1,702 PASS / 1 FAIL / 0 SKIP(`.local/aws-portfolio-01/full-final/`)

## 追加したファイル(56件、既存ファイルの変更は0件)

| 場所 | ファイル |
|---|---|
| `docs/aws_portfolio/` | README, ARCHITECTURE, TEST_RESULTS, OPEN_ITEMS, LIVE_ACCEPTANCE, RUNBOOK_GUARD_AND_AWS_A, RUNBOOK_AWS_B, RUNBOOK_AWS_C, COST_ESTIMATE, EVIDENCE_INDEX, ASSET_PRESERVATION, INTERVIEW_POINTS, HANDOFF |
| `infra/ops_guard/` | template.json, README.md |
| `infra/aws_b/` | template.json |
| `infra/aws_c/` | guard.template.json, worker.template.json, worker.stack-policy.json, user_data.sh |
| `src/aws_b/` | `__init__` model store probe handler view |
| `src/aws_c/` | `__init__` control controller watchdog s3_publisher signer evidence linux_launcher worker_entry |
| `tests/` | aws_fakes.py, cfn_contract.py, `aws_guard/`(1), `aws_b/`(7), `aws_c/`(8) |
| `tools/` | run_offline_tests.py, build_bundles.py, embed_user_data.py |

git管理外(`.local/aws-portfolio-01/`): 各回のテストログと `summary.json`。

## 作業中に下した小さな判断(記録)

| 判断 | 理由 |
|---|---|
| 既存 `docker_launcher.py` を編集せず、サブクラスでコンストラクタだけ差し替えた | 既存資産KEEP。基底クラスと属性集合が一致することをテストで固定 |
| AWS-BのClaimを制御項目への単一の条件付き更新にした | 停止・世代・重複・逆順を1回で判定でき、読取りと書込みの隙間が無い |
| AWS-Cのrun manifestを既存 `manifest.json` とは別ファイルにした | 既存の証拠形式を変えない |
| AWS-Cは準備済みマシンイメージを前提にし、起動時に何もインストールしない | 外向き通信を443のみにでき、過去のBuildKit想定外通信の教訓にも合う |
| KMS署名は既定で無効 | 必要性と費用が未承認 |
| 既存テスト1件の失敗は修正せず記録 | 既存ファイルの修正は承認範囲外 |
| Subagent(Sonnet)は運用ガードの4ファイルだけに使用 | 担当ファイルを分離。成果はレビューし、ハッシュ比較を改行差に強くする修正を1箇所加えた |

## 次に実行できること

承認なしで可能(オフライン):
1. 実IMDS・VPC DNS向けの追加負例(`RUNBOOK_AWS_C.md` §7)の実装とオフラインテスト。
2. マシンイメージ作成手順の設計(`OPEN_ITEMS.md` R8)。
3. AWS公式ドキュメントとの照合(`OPEN_ITEMS.md` §2)。通信を伴うため、照合作業自体の承認は必要。

USER承認が必要(順序つき。詳細は `OPEN_ITEMS.md` §3):
1. このworktreeの成果のcommit(P2)と、G1未追跡資産の保全commit(P1)。
2. 運用ガードのデプロイとAlarm実発火試験(U1, U2)。
3. AWS-BのLIVE(U4, U5)。
4. AWS-Cの準備と初回Pilot(U6〜U9)。

## 維持しているGate

v0.7 / v0.8 / v0.8.1 NOT ADOPTED / NOT FROZEN、LOCAL-ISOLATION NOT VERIFIED、formal T01〜T21 UNKNOWN、M5 PROFILE_UNATTESTED OPEN、AWS-B LIVE NO-GO、AWS-C Worker Pilot NO-GO、C-02 DEFERRED / OPEN。Search Fabric側は対象外で不変。

FAST TRACK優先順: AWS-B LIVE承認→正常/異常/重複/停止証拠→AWS-C実宛先隔離と本人サイト経路→別途AWS-C LIVE承認。AWS接続・外部通信・commit/push/mergeは未実施。
