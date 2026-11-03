import unittest

from tests._util import SCRIPTS  # noqa: F401
from appsec import cvss


class CVSSTest(unittest.TestCase):
    CASES = {
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": (9.8, "critical"),
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": (10.0, "critical"),
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": (6.1, "medium"),
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": (7.8, "high"),
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": (6.5, "medium"),
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N": (3.7, "low"),
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N": (0.0, "info"),
        "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H": (9.1, "critical"),
    }

    def test_known_vectors(self):
        for vec, (score, rating) in self.CASES.items():
            with self.subTest(vec=vec):
                self.assertEqual(cvss.score_and_rating(vec), (score, rating))

    def test_invalid(self):
        for bad in ("", "AV:N", "CVSS:3.1/AV:N", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):
            with self.subTest(bad=bad), self.assertRaises(cvss.CVSSError):
                cvss.base_score(bad)


if __name__ == "__main__":
    unittest.main()
