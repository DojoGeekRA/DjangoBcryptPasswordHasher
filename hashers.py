from collections import OrderedDict

import bcrypt
from django.utils.encoding import force_bytes
from django.utils.translation import ugettext_noop as _
from django.contrib.auth.hashers import mask_hash, BCryptPasswordHasher as PasswordHasher


class BcryptPasswordHasher(PasswordHasher):
    rounds = 10

    def verify(self, raw_password, hashed_password):
        """
        Checks if the given password is correct
        """
        return bcrypt.checkpw(raw_password, hashed_password)

    def encode(self, password, salt):
        """
        Creates a bcrypt hashed value.

        The result is formatted as "$mcf$cost$salt_and_hash" and has 60 characters.
        """
        hashed = super(self.__class__, self).encode(password, salt)

        return force_bytes(hashed[7:])

    def safe_summary(self, hashed):
        """
        Returns a summary of safe values

        The result is a dictionary and will be used where the password field
        must be displayed to construct a safe representation of the password.
        """
        mcf, cost, data = hashed[1:].split('$', 4)
        salt, checksum = data[:22], data[22:]
        return OrderedDict([
            (_('algorithm'), self.algorithm),
            (_('work factor'), cost),
            (_('salt'), mask_hash(salt)),
            (_('checksum'), mask_hash(checksum)),
        ])

    def must_update(self, hashed):
        """
        Checks if the password must be updated.
        """
        mcf, cost, data = hashed[1:].split('$', 4)
        return int(cost) != self.rounds

    def harden_runtime(self, password, hashed):
        """
        Bridge the runtime gap between the work factor supplied in `encoded`
        and the work factor suggested by `BCryptPasswordHasher`.
        """
        mcf, cost, data = hashed[1:].split('$', 4)
        salt, checksum = data[:22], data[22:]
        # work factor is logarithmic, adding one doubles the load.
        diff = 2**(self.rounds - int(cost)) - 1
        while diff > 0:
            self.encode(password, force_bytes(salt))
            diff -= 1
