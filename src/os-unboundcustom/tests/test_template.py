"""Render actual custom directives without altering their text or disabled state."""
from pathlib import Path
import unittest
from jinja2 import Environment, FileSystemLoader

PACKAGE = Path(__file__).resolve().parents[1]


class TemplateTests(unittest.TestCase):
    def render(self, general=None):
        data = {'OPNsense': {'unboundcustom': {'general': general}}} if general is not None else {}
        class Helpers:
            def exists(self, path):
                return general is not None and 'enabled' in general
        template = Environment(loader=FileSystemLoader(str(
            PACKAGE / 'src/opnsense/service/templates/OPNsense/Unboundcustom'))).get_template('custom-options.conf')
        return template.render(**data, helpers=Helpers())

    def test_enabled_directives_are_inserted_verbatim_including_comments_and_crlf(self):
        raw = '# 中文 comment\r\nserver:\r\n  verbosity: 2\r\n  private-domain: "example.invalid"\r\n'
        self.assertIn(raw, self.render({'enabled': '1', 'customoptions': raw}))

    def test_disabled_missing_or_partial_settings_do_not_generate_directives(self):
        for general in [None, {}, {'enabled': '0', 'customoptions': 'INVALID_DISABLED_DIRECTIVE'},
                        {'customoptions': 'INVALID_MISSING_FLAG_DIRECTIVE'}]:
            with self.subTest(general=general):
                self.assertEqual(self.render(general).strip(), '')


if __name__ == '__main__':
    unittest.main()
