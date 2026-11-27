"""Static checks of the app's browser script and styles (src/noxiworks/app_assets/app.js, app.css): the way every action reaches the server, no data into HTML,
the words the screens must and must not contain. The behaviour in a real browser is checked by hand; here nothing runs but `node --check` (skipped without node)."""
from pathlib import Path
import re
import shutil
import subprocess
import unittest

ASSETS = Path(__file__).resolve().parents[2] / 'src' / 'noxiworks' / 'app_assets'
JS = (ASSETS / 'app.js').read_text('utf-8')
CSS = (ASSETS / 'app.css').read_text('utf-8')
NODE = shutil.which('node')


def function_body(name):
    start = JS.index('function ' + name + '(')
    nxt = re.search(r'\n  (?:async )?function \w+\(|\n  // ----', JS[start + 10:])
    return JS[start:start + 10 + nxt.start()] if nxt else JS[start:]


@unittest.skipUnless(NODE, 'node not available')
class Syntax(unittest.TestCase):
    def test_the_script_parses(self):
        done = subprocess.run([NODE, '--check', str(ASSETS / 'app.js')], capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr[-800:])


class Requests(unittest.TestCase):
    def test_one_function_sends_every_post_and_it_names_the_site(self):
        self.assertEqual(len(re.findall(r'\bfetch\(', JS)), 2)  # the one GET helper (the session, 導入環境の確認) and that one POST
        self.assertEqual(len(re.findall(r"method: 'POST'", JS)), 1)
        post = function_body('post')
        self.assertIn("method: 'POST'", post)
        self.assertIn('{site_id: pageSite, unit: pageUnit}', post)  # the site AND the page of the tab
        self.assertIn("route !== '/app/api/site/register'", post)  # a new site has no id yet
        self.assertLess(post.index('{site_id: pageSite, unit: pageUnit}'), post.index('JSON.stringify'))
        self.assertIn('Object.assign({token: fresh.token}, own, body)', post)  # the caller's own site_id (an all-sites card) wins over the page's
        calls = [m.start() for m in re.finditer(r'\bpost\(', JS)]
        self.assertEqual(len(calls), 2)  # the definition and the one call inside action()
        self.assertIn('await post(', function_body('action'))

    def test_every_site_route_is_one_the_server_knows_and_is_reached_through_the_helpers(self):
        routes = set(re.findall(r"'(/app/api/site/[a-z-]+)'", JS))
        self.assertEqual(routes, {'/app/api/site/register', '/app/api/site/monitor', '/app/api/site/inspect', '/app/api/site/confirm', '/app/api/site/setup',
                                  '/app/api/site/baseline-update', '/app/api/site/baseline-approve', '/app/api/site/http', '/app/api/site/notify', '/app/api/site/maintenance',
                                  '/app/api/site/backup', '/app/api/site/add-page', '/app/api/site/stop-site'})
        from src.noxiworks import app as app_module
        self.assertEqual(routes, set(app_module.SITE_ROUTES))
        for route in routes - {'/app/api/site/register'}:  # each is the argument of action() or of decision() (which calls action()) -- never of a bare fetch
            self.assertRegex(JS, r"(action|decision)\([^;]*'" + route + "'")

    def test_the_session_is_asked_for_the_site_of_the_page(self):
        self.assertIn(r"/^\/site\/(site-[0-9a-f]{8})\/(?:page\/(site-[0-9a-f]{8}-p[2-9])\/)?/.exec(path)", JS)  # a first page or a further page
        self.assertIn("'/app/api/session' + (siteId ? '?site=' + siteId + (pageId ? '&page=' + pageId : '') : '')", JS)
        self.assertEqual(len(re.findall(r"/app/api/session", JS)), 1)

    def test_pages_under_a_site_are_recognised_like_the_top_pages(self):
        self.assertIn("var rel = siteId ? path.slice(('/site/' + siteId + (pageId ? '/page/' + pageId : '')).length) : path;", JS)
        self.assertIn("indexOf(rel) >= 0", JS)  # HOME: '/', '/index.html' also under /site/<id>/
        self.assertEqual(re.findall(r'\.test\(path\)', JS), [])  # the review / activity / details tests use the page's own path inside the site
        self.assertEqual(len(re.findall(r'\.test\(rel\)', JS)), 2)

    def test_links_stay_inside_the_site_prefix(self):
        allowed = {'review.html', 'activity.html', '/demo/', '/', '#baseline-update-panel', '#'}  # '#': the in-page jump links (jump(id, ...)), which only move inside the page
        found = set(re.findall(r"href: '([^']*)'", JS))
        self.assertEqual(found - allowed, set())  # relative pages, the demo, the all-sites list; the cards use the server's own href
        self.assertIn("href: o.href", JS)
        self.assertIn("OWN_PAGE.test(target)", JS)  # a redirect after registering is only ever to a site's own pages
        self.assertIn(r"var OWN_PAGE = /^\/site\/site-[0-9a-f]{8}\/(?:page\/site-[0-9a-f]{8}-p[2-9]\/)?$/;", JS)

    def test_the_reload_watch_follows_the_new_panels_and_the_list_without_wiping_forms(self):
        watch = function_body('watch')
        for needle in ('h.last_at', 'h.paused_reason', 'last.at', 'last.result', 's.background_http', 'listKey', 'form[aria-busy]', '#storage-panel[open]', '#site-add-more[open]',
                       '#site-add-form:not([hidden])', 'INPUT|SELECT|TEXTAREA'):
            self.assertIn(needle, watch)


class NoDataIntoHtml(unittest.TestCase):
    def test_text_only(self):
        for forbidden in ('innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'srcdoc'):
            self.assertNotIn(forbidden, JS, forbidden)
        self.assertIn('node.textContent = text', function_body('el'))
        self.assertIsNone(re.search(r"setAttribute\('(on\w+|style)'", JS))
        self.assertNotIn('createContextualFragment', JS)


class Words(unittest.TestCase):
    def test_a_send_is_never_called_a_receipt(self):
        for forbidden in ('配信完了', '受信しました', '届きました', '到着しました'):
            self.assertNotIn(forbidden, JS)
        for m in re.finditer('受信', JS):
            self.assertRegex(JS[m.start():m.start() + 8], r'^受信(は未確認|を保証|\（|の)', JS[m.start() - 12:m.start() + 12])
        self.assertIn('受信は未確認', JS)

    def test_the_pieces_the_user_looks_for_are_there(self):
        needles = ('sites-panel', '全サイトの状態', '確認が必要なものはありません', 'このサイトを開く ›', 'site-switcher', '‹ 全サイトの状態', '別のサイトを追加', '同じサイトのページは、登録後に最大5ページまで追加できます', 'pages-panel', 'ownership-panel', 'page-add-form', 'page-switcher', 'site-stop-all-form',
                   'このサイトの監視をすべて停止', 'ページを追加', "step: 'dns-issue'", "step: 'dns-check'", 'ownership-record-value', 'http-not-run', '検査していません',
                   '今すぐ検査', 'HTTP監視の許可に署名する', "step: 'http-grant'", '観測がない期間', '履歴を整理（別ファイルへ移す）', "'archive-http'", '削除はしません', '隔離コンテナで1回ずつ実行します（コンテナの境界は',
                   '限定試験', "'background-http'", "'background-http-remove'", "'background-remove'", 'site-background-http', 'notify-panel', 'メール通知', 'テスト通知を送る', "what: 'test'",
                   "what: 'kinds'", "what: t[0]", 'SiteProof-SMTP-', 'tools/notify_grant.py', 'Windowsの「資格情報マネージャー」', 'storage-panel', "'archive-notifications'", '通知の履歴を整理',
                   '全データをバックアップ', 'このサイトだけバックアップ', "scope: 'all'", "scope: 'site'", '復元は手動です', 'どこにも送信しません', '既存のデータは削除しません',
                   's.permit_notice', 's.stop_text', 'h.grant_notice', 'h.stop_text', 'state.max_sites', 'site_problems', 'このサイトのメール通知を')
        for needle in needles:
            self.assertIn(needle, JS, needle)
        self.assertNotIn('登録できるのは1サイト・1ページです', JS)
        for stale in ('Dockerもブラウザも使いません', 'OS・ネットワークレベルの隔離ではありません'):  # the HTTP check runs in an isolated one-shot container (Docker Desktop needed)
            self.assertNotIn(stale, JS)

    def test_a_stopped_or_unobserved_site_is_never_called_normal_by_the_script(self):
        cards = function_body('siteCard')
        self.assertNotIn('正常', cards)  # the card shows the server's own labels (停止中 / 未監視 / 長期間未観測 ...)
        self.assertIn('im.label', cards)
        self.assertIn('ht.state_label', cards)

    def test_attention_comes_first_and_a_start_that_cannot_happen_is_disabled_with_its_reason(self):
        panel = function_body('sitesPanel')
        self.assertIn("(b.attention || []).length > 0) - ((a.attention || []).length > 0)", panel)
        cards = function_body('siteCard')
        self.assertIn('im.start_block', cards)
        self.assertIn('ht.start_block', cards)
        self.assertIn("setAttribute('disabled', '')", cards)
        self.assertIn('o.site_id', cards)  # a card names its own site in its own POSTs

    def test_the_check_button_is_disabled_for_the_same_reasons_as_starting(self):
        http = function_body('httpPanel')
        self.assertIn("if (h.start_block) check.setAttribute('disabled', '')", http)
        self.assertIn("{what: 'check'}", http)

    def test_stylesheet_has_the_new_blocks(self):
        for needle in ('.app-site-card', '.app-site-switcher', '.app-site-cards', '.app-group', '.app-table', '.app-external', '.app-steps-list', '.app-overview', '.app-sr-only'):
            self.assertIn(needle, CSS)

    def test_the_site_screen_has_the_six_groups_in_the_order_a_person_needs(self):
        screen = function_body('siteScreen')
        self.assertEqual(re.findall(r"groupHeading\('(group-[a-z]+)'", screen), ['group-summary', 'group-image', 'group-http', 'group-notify', 'group-permits', 'group-storage'])
        positions = [screen.index(x) for x in ('1. 要約', '2. 画像監視', '3. HTTP監視', '4. 通知', '5. 所有権と許可', '6. 保存・導入')]
        self.assertEqual(positions, sorted(positions))
        calls = [screen.index(x + '(state)') for x in ('summaryPanel', 'sitePanel', 'httpPanel', 'notifyPanel', 'noticeHistoryPanel', 'permitsPanel', 'ownershipPanel', 'storagePanel', 'environmentPanel')]
        self.assertEqual(calls, sorted(calls))
        self.assertIn('siteScreen(state)', function_body('render'))
        self.assertIn("'画像監視：' + s.name", function_body('sitePanel'))  # image and HTTP are told apart by their headings
        self.assertIn("'HTTP監視（サイトの死活）'", function_body('httpPanel'))
        self.assertIn('backgroundHttpBlock(state.site)', function_body('httpPanel'))  # the HTTP task lives with the HTTP check
        self.assertNotIn('backgroundHttpBlock', function_body('sitePanel'))
        for kept in ('site-summary', 'site-control', 'site-readiness', 'site-background', 'ownership-panel', 'storage-panel', 'pages-panel', 'notify-panel', 'http-panel'):
            self.assertIn(kept, JS)

    def test_external_communication_is_one_quiet_line_that_names_what_is_off(self):
        banner = function_body('externalBanner')
        for needle in ("'external-panel'", 'HTTP監視', 'メール', 'DNS確認', 'external_enabled', 'dns_check_enabled', '何も送信・問い合わせしていません', '=== false'):
            self.assertIn(needle, banner)
        self.assertNotIn('is-error', banner)  # not an alarm
        self.assertNotIn('is-warn', banner)
        rule = CSS[CSS.index('.app-external {'):].split('}', 1)[0]
        self.assertNotIn('#b42318', rule)

    def test_the_permits_table_has_the_four_rows_and_levels_from_the_servers_notices(self):
        rows = function_body('permitRows')
        for needle in ("key: 'ownership'", "key: 'image'", "key: 'http'", "key: 'notify'", 's.permit_notice', 'h.grant_notice', 'min_interval_seconds', 'PURPOSE', 'remaining_runs', 'max_requests', 'remaining_total'):
            self.assertIn(needle, rows)
        self.assertIn('permitLevel(pm, s.permit_notice)', rows)
        self.assertIn('grantLevel(g, h.grant_notice)', rows)
        panel = function_body('permitsPanel')
        for needle in ("'permits-panel'", "'permits-table'", "scope: 'col'", "scope: 'row'", 'LEVEL_MARK', 'permits-notices', 'app-sr-only'):
            self.assertIn(needle, panel)
        self.assertIn('cardPermits(o)', function_body('siteCard'))  # expired and near-expiry are on the site card too
        self.assertIn("'許可の期限'", function_body('siteCard'))
        for word in ('期限切れ', 'まもなく期限'):
            self.assertIn(word, function_body('cardPermits'))

    def test_the_notice_history_filters_by_kind_in_the_browser_and_takes_its_wording_from_the_server(self):
        panel = function_body('noticeHistoryPanel')
        for needle in ("'notice-filter'", 'data-kind', 'kind_label', 'delivery_label', "'for': 'notice-filter'", 'hidden'):
            self.assertIn(needle, panel)
        self.assertNotIn('fetch(', panel)  # filtered on the page; no request
        for composed_here in ('delivery.sink', 'd.sink', 'deliveryText'):
            self.assertNotIn(composed_here, JS)
        self.assertIn('受信を保証しません', panel)

    def test_what_was_not_checked_is_not_a_failure_or_an_undecided_result(self):
        note = function_body('notRunNotice')
        self.assertIn('検査していません', note)
        self.assertIn('is-info', note)
        self.assertNotIn('is-error', note)
        self.assertIn('サイトの障害とは限りません', note)
        self.assertIn('notRunNotice(h.not_run)', function_body('httpPanel'))
        self.assertIn('ht.not_run', function_body('siteCard'))
        self.assertIn('NOT_RUN_REASON', JS)

    def test_the_first_steps_come_from_the_servers_facts_and_can_be_dismissed_safely(self):
        steps = function_body('firstSteps')
        order = [steps.index("key: '" + k + "'") for k in ('environment', 'site', 'ownership', 'permit', 'monitor', 'background', 'mail')]
        self.assertEqual(order, sorted(order))
        for fact in ('env.ok', 's.site_id', "o.status === 'VERIFIED'", "o.status === 'VERIFIED'", 'pm.expired', 'm.enabled', 's.background === true', 'n.active'):
            self.assertIn(fact, steps)
        self.assertIn('s.background === null', steps)  # a question that could not be asked is never "done"
        panel = function_body('firstStepsPanel')
        for word in ("'first-steps'", '済み', '次にすること', '不要・必要なときだけ'):
            self.assertIn(word, panel)
        for storage in ('stepsHidden', 'rememberStepsHidden'):  # localStorage only ever inside try / catch
            body = function_body(storage)
            self.assertIn('try {', body)
            self.assertIn('catch (e)', body)
        self.assertEqual(len(re.findall(r'localStorage', JS)), len(re.findall(r'localStorage', function_body('stepsHidden') + function_body('rememberStepsHidden'))))
        self.assertIn('function jump(id, text)', JS)

    def test_the_environment_panel_is_folded_loaded_on_demand_and_read_only(self):
        panel = function_body('environmentPanel')
        self.assertIn("el('details'", panel)
        self.assertIn("addEventListener('toggle'", panel)
        self.assertIn("read('/app/api/environment')", panel)
        self.assertNotIn('post(', panel)
        self.assertEqual(len(re.findall(r'/app/api/environment', JS)), 1)
        self.assertIn('#environment-panel[open]', function_body('watch'))  # a reload never wipes the opened report


class Usability(unittest.TestCase):
    def test_keyboard_focus_is_always_visible(self):
        self.assertIsNone(re.search(r'outline:\s*(none|0)\b', CSS))
        for target in ('a:focus-visible', 'summary:focus-visible', 'input:focus-visible', 'select:focus-visible', 'button:focus-visible'):
            self.assertIn(target, CSS)

    def test_every_input_the_script_makes_has_a_label(self):
        for m in re.finditer(r"el\('(?:input|select)', \{[^}]*?id: '([\w-]+)'", JS):
            ident = m.group(1)
            self.assertRegex(JS, r"(?:'for'|for): '" + re.escape(ident) + "'", ident)
        for dynamic in ("'for': 'site-kind-' + k", "'for': 'page-kind-' + k", "'for': 'notify-kind-' + k", "'for': id + '-ok'", "'for': 'notice-filter'"):
            self.assertIn(dynamic, JS)

    def test_no_horizontal_overflow_at_500px(self):
        narrow = CSS[CSS.index('@media (max-width: 520px) {  /* the tables become stacked cards'):]
        for needle in ('.app-table', 'display: block', 'box-sizing: border-box', 'attr(data-label)'):
            self.assertIn(needle, narrow)
        for needle in ('overflow-wrap: anywhere', '.app-table-wrap', '[hidden] { display: none !important; }'):
            self.assertIn(needle, CSS)

    def test_a_status_is_never_only_a_colour(self):
        for mark_source in ("LEVEL_MARK = {ok: '✓', warn: '⚠', error: '✗', none: '—'}", "ENV_MARK = {OK: '✓ OK', MISSING: '✗ ない', WARN: '⚠ 注意', UNKNOWN: '？ 不明'}", "SEVERITY_TEXT = {critical: ['✗', '重大'"):
            self.assertIn(mark_source, JS)
        self.assertIn('LEVEL_MARK[r.level]', function_body('permitsPanel'))



class AllSitesHeader(unittest.TestCase):
    def test_the_all_sites_home_fills_the_header_from_real_observations_only(self):
        body = function_body('sitesHeader')
        self.assertIn("(o.runs || 0) > 0", body)  # a "not ready" pass without a capture is no observation
        self.assertIn('q.http.last_at', body)
        self.assertIn("'未取得'", body)  # nothing observed stays 未取得
        self.assertIn('sitesHeader(state)', function_body('render'))


if __name__ == '__main__':
    unittest.main()
