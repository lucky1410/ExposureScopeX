import unittest

from pydantic import ValidationError

from app.security import Credentials, password_digest


class AuthenticationTests(unittest.TestCase):
    def test_password_digest_is_deterministic_for_same_salt(self) -> None:
        salt = bytes(range(16))
        first = password_digest("A-strong-local-password", salt)
        second = password_digest("A-strong-local-password", salt)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)

    def test_password_digest_changes_with_salt(self) -> None:
        first = password_digest("A-strong-local-password", bytes(range(16)))
        second = password_digest("A-strong-local-password", bytes(range(1, 17)))
        self.assertNotEqual(first, second)

    def test_email_is_normalized(self) -> None:
        credentials = Credentials(email="  ADMIN@ESX.COM ", password="A-strong-local-password")
        self.assertEqual(credentials.email, "admin@esx.com")

    def test_short_password_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            Credentials(email="admin@esx.com", password="too-short")


if __name__ == "__main__":
    unittest.main()
