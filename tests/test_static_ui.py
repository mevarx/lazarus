import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "static"


class StaticUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = {path.name: path.read_text(encoding="utf-8") for path in STATIC.iterdir() if path.is_file()}
        cls.source = "\n".join(cls.files.values())

    def test_page_uses_external_first_party_assets_only(self):
        html = self.files["index.html"]
        self.assertRegex(html, r'<script\s+src="/app\.js"\s+defer>')
        self.assertIn('href="/styles.css"', html)
        self.assertNotRegex(self.source, r"(?is)<script(?![^>]*\bsrc\s*=)[^>]*>")
        self.assertNotRegex(self.source, r"(?i)\son[a-z]+\s*=")
        self.assertNotRegex(self.source, r"(?i)\sstyle\s*=")

    def test_no_external_assets_or_template_branding(self):
        allowed_namespace = "http://www.w3.org/2000/svg"
        urls = re.findall(r"https?://[^\s\"'`<>)]*", self.source, flags=re.IGNORECASE)
        self.assertTrue(all(url == allowed_namespace for url in urls), urls)
        lowered = self.source.lower()
        for brand in ("capitalio", "watermelon"):
            self.assertNotIn(brand, lowered)
        self.assertNotIn("fonts.googleapis", lowered)

    def test_api_text_is_rendered_without_html_parsing(self):
        script = self.files["app.js"]
        self.assertNotRegex(script, r"(?i)\binnerhtml\b")
        self.assertIn("textContent", script)
        self.assertIn("createElementNS", script)
        self.assertIn("replace(EMAIL_PATTERN, \"[redacted email]\")", script)

    def test_comparison_and_provider_contract_are_present(self):
        script = self.files["app.js"]
        for contract_field in (
            "/api/compare?domain=",
            "agreement?.status",
            "rules.risk",
            "rules.severity",
            "gemma.evidence",
            "gemma.risk_reasoning",
            "gemma.disclosure_email",
            "provider.fallback_chain",
            "models_verified === false",
        ):
            self.assertIn(contract_field, script)
        self.assertIn('family !== "Gemma 4"', script)
        self.assertIn('family !== "Gemma 3"', script)
        self.assertIn("state.recentScanMode", script)
        self.assertIn("Fell back from ${cleanText(provider.degraded_from)}.", script)
        self.assertIn('element("summary", "", "Fallback chain")', script)
        self.assertIn("Retry comparison", script)

    def test_blast_radius_and_replay_copy_are_explicit(self):
        html = self.files["index.html"]
        self.assertIn("Only CRITICAL and HIGH domains count. MEDIUM and LOW are excluded.", html)
        self.assertIn("REPLAY · recorded data, not a live scan", html)
        self.assertIn("Risk flags are heuristics, not proof of compromise.", html)
        self.assertIn("radius.combined_weekly_downloads", self.files["app.js"])
        self.assertIn("node.type || \"\").toLowerCase()", self.files["app.js"])
        self.assertIn("for (const finding of state.findings)", self.files["app.js"])

    def test_scan_control_uses_the_supported_event_stream_modes(self):
        script = self.files["app.js"]
        self.assertIn('mode === "live" ? "live=1" : "demo=1"', script)
        self.assertIn("new EventSource(`/api/run?${params}`)", script)
        self.assertIn('stream.addEventListener("done"', script)

    def test_no_api_key_literal_or_third_party_request(self):
        self.assertNotRegex(self.source, r"AIza[0-9A-Za-z_-]{35,}")
        self.assertNotIn("GEMINI_API_KEY", self.source)
        self.assertNotRegex(self.files["app.js"], r"fetch\(\s*[`\"]https?://")
        self.assertIn("[redacted secret]", self.files["app.js"])


if __name__ == "__main__":
    unittest.main()
