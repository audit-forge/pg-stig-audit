#!/usr/bin/env python3
"""Unit tests for pg-stig-audit check modules."""
import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from checks.base import Status, Severity


class SmokeTests(unittest.TestCase):
    def test_check_modules_import(self):
        """Verify all check modules can be imported."""
        from checks import config, auth, logging, privileges
        self.assertIsNotNone(config.ConfigChecker)
        self.assertIsNotNone(auth.AuthChecker)
        self.assertIsNotNone(logging.LoggingChecker)
        self.assertIsNotNone(privileges.PrivilegesChecker)
    
    def test_output_modules_import(self):
        """Verify all output modules can be imported."""
        from output import report, sarif, wiz_scc, bundle
        self.assertIsNotNone(report.render)
        self.assertIsNotNone(sarif.write)
        self.assertIsNotNone(wiz_scc.write_wiz)
        self.assertIsNotNone(bundle.write)


if __name__ == "__main__":
    unittest.main()
