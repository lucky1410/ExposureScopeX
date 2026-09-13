import unittest

from app.secrets import decrypt_secret, encrypt_secret


class SecretTests(unittest.TestCase):
    def test_assessment_credentials_are_encrypted_at_rest(self) -> None:
        plaintext = "authorized-test-password"
        ciphertext = encrypt_secret(plaintext)
        self.assertNotIn(plaintext.encode(), ciphertext)
        self.assertEqual(decrypt_secret(ciphertext), plaintext)


if __name__ == "__main__":
    unittest.main()
