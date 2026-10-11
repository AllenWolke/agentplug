import json
import pathlib
import subprocess
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class ProductizationBaselineTest(unittest.TestCase):
    def test_contract_checker(self):
        proc = subprocess.run([sys.executable, str(ROOT / "scripts/check_agent_productization_contracts.py")], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(json.loads(proc.stdout)["ok"])

    def test_ownership_checker(self):
        proc = subprocess.run([sys.executable, str(ROOT / "scripts/check_agent_code_ownership.py")], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
