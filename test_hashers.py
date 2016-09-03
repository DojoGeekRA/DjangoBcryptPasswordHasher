import bcrypt
import unittest

from django.conf import settings as django_settings

from hashers import BcryptPasswordHasher


class TestBcryptHasher(unittest.TestCase):

    def setUp(self):
        self.hasher = BcryptPasswordHasher()

    def test_that_it_hashes_with_ten_rounds(self):
        self.assertEqual(self.hasher.rounds, 10)

    def test_that_it_verifies_hashed_passwords(self):
        hashed = self.hasher.encode('password', bcrypt.gensalt(self.hasher.rounds))

        self.assertTrue(
            self.hasher.verify('password', hashed)
        )
        self.assertFalse(
            self.hasher.verify('wrong_password', hashed)
        )

    def test_that_hashed_passwords_does_not_have_the_algorithm_prefix(self):
        hashed = self.hasher.encode('password', bcrypt.gensalt(self.hasher.rounds))

        self.assertFalse(
            hashed.startswith('%s$' % self.hasher.algorithm)
        )

    def test_that_it_provides_a_safe_summary(self):
        hashed = self.hasher.encode('password', bcrypt.gensalt(self.hasher.rounds))

        summary = self.hasher.safe_summary(hashed)

        self.assertEqual(summary['algorithm'], 'bcrypt')
        self.assertEqual(
            int(summary['work factor']), self.hasher.rounds
        )

    def test_that_hashed_passwords_with_different_cost_factors_should_be_updated(self):
        valid_hash = self.hasher.encode('password', bcrypt.gensalt(self.hasher.rounds))
        need_update = self.hasher.encode('password', bcrypt.gensalt(self.hasher.rounds - 1))

        self.assertFalse(
            self.hasher.must_update(valid_hash)
        )
        self.assertTrue(
            self.hasher.must_update(need_update)
        )

    def test_that_it_hardens_the_runtime_to_the_suggested_by_the_hasher(self):
        hashed = self.hasher.encode('password', bcrypt.gensalt(self.hasher.rounds))

        # This one is hard to test. In the meantime, i just make sure it follows the
        # `BCryptPasswordHasher` pattern and it plays nicely with the new hashed format.
        self.hasher.harden_runtime('password', hashed)

if __name__ == '__main__':
    django_settings.configure()
    unittest.main()
