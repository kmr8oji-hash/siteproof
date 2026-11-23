"""Static contract tests for the Penpot-realigned HOME layout (web/home).

Scope: text/structure checks of the shipped files only. They do NOT render the page,
so they are not a visual or browser-measured verification.
Standard library only; no browser, no network.
"""

import re
import unittest

from test_home_static import HomeTestBase


class SectionOrderTests(HomeTestBase):
    def main_blocks(self):
        main = self.find("main")[0]
        out = []
        for child in main.children:
            if child.tag == "section":
                out.append(child.attrs.get("id")
                           or ("status-panel" if "status-panel" in child.classes() else "other"))
            elif "home-grid" in child.classes():
                out.append("home-grid")
        return out

    def test_order_status_dashboard_aws_then_auxiliary_regions(self):
        self.assertEqual(self.main_blocks(),
                         ["status-panel", "home-grid", "aws-sample", "flow-demo",
                          "result-viewer", "sample-details"])

    def test_launchers_are_two_columns_three_rows_with_decorative_chevrons(self):
        grid = next(n for n in self.nodes if "launcher-grid" in n.classes())
        launchers = [c for c in grid.children if "launcher" in c.classes()]
        self.assertEqual(len(launchers), 6)
        for button in launchers:
            chevrons = [c for c in button.walk() if "launcher-chevron" in c.classes()]
            self.assertEqual(len(chevrons), 1)
            self.assertEqual(chevrons[0].attrs.get("aria-hidden"), "true")
        # Non-interactive cards and log rows must not carry a fake "open" affordance.
        for node in self.nodes:
            if "status-card" in node.classes() or "log-row" in node.classes():
                self.assertFalse([c for c in node.walk() if "chevron" in " ".join(c.classes())])

    def test_header_tools_are_decorative_and_not_controls(self):
        tools = next(n for n in self.nodes if "header-tools" in n.classes())
        self.assertEqual(tools.attrs.get("aria-hidden"), "true")
        header = self.find("header")[0]
        self.assertEqual([n.tag for n in header.walk() if n.tag in ("button", "input", "select")], [])
        self.assertEqual([n.attrs.get("href") for n in header.walk() if n.tag == "a"],
                         ["../compare/index.html"])


class LatestLogStructureTests(HomeTestBase):
    def rows(self):
        return [n for n in self.nodes if "log-row" in n.classes()]

    def test_each_row_has_event_target_and_synthetic_time(self):
        for row in self.rows():
            event = next(c for c in row.children if "log-event" in c.classes())
            target = next(c for c in event.children if "log-target" in c.classes())
            self.assertRegex(target.full_text(), r"^/[a-z]+/（架空の対象）$")
            clock = next(c for c in row.children if "log-time" in c.classes())
            self.assertRegex(clock.full_text(), r"^合成時刻\s*\d{2}:\d{2}$")
            self.assertNotIn("datetime", clock.attrs)
            self.assertEqual([c for c in row.walk() if c.tag == "time"], [])

    def test_five_semantic_states_stay_distinct_and_ordered(self):
        states = [next(c for c in r.walk() if "status-badge" in c.classes()).full_text()
                  for r in self.rows()]
        self.assertEqual(states, ["COMPLETED", "PASS", "CHANGED", "APPROVED", "UNKNOWN"])
        self.assertEqual(len(set(states)), 5)

    def test_completed_is_not_conflated_with_pass(self):
        completed = next(r for r in self.rows() if r.attrs["data-log-status"] == "completed")
        self.assertNotIn("PASS", completed.full_text())
        self.assertIn("品質の良し悪しではありません", completed.full_text())

    def test_log_header_is_a_dark_bar_with_demo_marker(self):
        bar = next(n for n in self.nodes if "log-bar" in n.classes())
        self.assertIn("DEMO", bar.full_text())
        self.assertRegex(self.css_code, r"\.log-bar\s*\{[^}]*background\s*:\s*var\(--navy\)")


class WordingScopeTests(HomeTestBase):
    def test_sample_wording_is_scoped_to_synthetic_content(self):
        footer = self.find("footer")[0].full_text()
        self.assertNotIn("この画面のデータはすべてサンプル", footer)
        self.assertIn("架空のサンプル", footer)
        self.assertIn("未認証のファイルの主張", footer)

    def test_viewer_is_labelled_untrusted_not_sample(self):
        viewer = self.by_id("result-viewer")
        flags = [n.full_text() for n in viewer.walk() if "flow-flag" in n.classes()]
        self.assertIn("OFFLINE REPORT / UNTRUSTED FILE", flags)
        self.assertNotIn("SAMPLE DATA", viewer.full_text())
        self.assertEqual(viewer.full_text().count("ローカルファイルから読み込んだ未認証レポート"), 2)

    def test_synthetic_flow_keeps_its_sample_label(self):
        flow = self.by_id("flow-demo")
        self.assertIn("SAMPLE DATA / OFFLINE DEMO", flow.full_text())

    def test_open_gates_remain_visible_in_page(self):
        text = self.page_text()
        for needle in ("LOCAL-ISOLATION NOT VERIFIED", "AWS LIVE NO-GO", "UNATTESTED",
                       "Production Profile Trust Source OPEN"):
            self.assertIn(needle, text)


class FocusSafeShapeTests(HomeTestBase):
    def test_focusable_elements_are_not_clipped_by_clip_path(self):
        # Launchers draw their cut corners inside the box, so no clip-path may shape them
        # (a clip-path would cut off the focus outline). The same holds for the header link.
        for selector in (".launcher", ".launcher-primary", ".launcher-secondary",
                         ".site-header", ".header-link", ".header-link a", ".header-inner"):
            for selectors, body in re.findall(r"([^{}]+)\{([^{}]*)\}", self.css_code):
                if selector in [s.strip() for s in selectors.split(",")]:
                    self.assertNotIn("clip-path", body, selector)

    def test_focus_bearing_ancestors_do_not_clip_or_hide_overflow(self):
        # Outlines are drawn outside the box, so any ancestor that clips would cut them off.
        ancestors = (".site-header", ".header-inner", ".header-left", ".header-link",
                     ".header-bar", ".main", ".home-grid", ".launcher-section", ".launcher-grid",
                     ".aws-text", ".aws-actions", "body", "html")
        for selectors, body in re.findall(r"([^{}]+)\{([^{}]*)\}", self.css_code):
            hit = [s.strip() for s in selectors.split(",") if s.strip() in ancestors]
            if hit:
                self.assertNotRegex(body, r"overflow(-[xy])?\s*:\s*(hidden|clip)", hit)
                self.assertNotIn("clip-path", body, hit)
                self.assertNotIn("contain:", body, hit)

    def test_log_rows_keep_full_explanations_in_accessible_text(self):
        for row in [n for n in self.nodes if "log-row" in n.classes()]:
            expl = next(c for c in row.children if "log-expl" in c.classes())
            self.assertIn("sr-only", expl.classes())
            self.assertTrue(expl.full_text())
        self.assertNotRegex(self.css_code, r"\.log-[a-z-]+\s*\{[^}]*(?<![-\w])height\s*:")

    def test_footer_does_not_claim_user_files_are_not_samples(self):
        footer = self.find("footer")[0].full_text()
        self.assertNotIn("サンプルではありません", footer)
        self.assertIn("内蔵合成デモとは別", footer)
        self.assertIn("未認証", footer)

    def test_clip_path_only_on_non_interactive_shapes(self):
        for selectors, body in re.findall(r"([^{}]+)\{([^{}]*)\}", self.css_code):
            if "clip-path" not in body:
                continue
            for selector in (s.strip() for s in selectors.split(",")):
                self.assertTrue(
                    selector in (".status-panel", ".log-section", ".aws-section", ".sr-only")
                    or selector.endswith("::before") or selector.endswith("::after")
                    or selector == ".badge", selector)

    def test_desktop_header_is_full_bleed_and_inner_width_capped(self):
        self.assertRegex(self.css_code, r"\.header-inner\s*\{[^}]*max-width\s*:\s*1440px")
        self.assertRegex(self.css_code, r"\.main\s*\{[^}]*max-width\s*:\s*1440px")

    def test_three_viewport_breakpoints_exist(self):
        widths = {int(w) for w in re.findall(r"@media\s*\(max-width:\s*(\d+)px\)", self.css_code)}
        self.assertTrue({560, 900, 1100, 1340} <= widths)


if __name__ == "__main__":
    unittest.main()
