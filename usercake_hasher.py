from django.contrib.auth.hashers import BasePasswordHasher
from collections import OrderedDict
from django.utils.translation import ugettext_noop as _
from django.utils.crypto import get_random_string
import hashlib

class UserCakePasswordHasher(BasePasswordHasher):
    """
        Authenticate against Usercake passwords in Django.
        (http://usercake.com/)

        Use this class to authenticate against Usercake password strings. When importing passwords from Usercake, the database values should be prefixed with "usercake$".

        Usercake passwords consist of a 65 character string.
        The first 25 characters are the salt
        The next block of 40 characters is the password encrypted using Sha1 and the salt

        h = UserCakePasswordHasher()
        h.verify("123456789", "usercake$860b4cefa917c430ed85d89525e0158d5be9e1515333a9dcfefd51a2419a119d1")
        >>>>True

        r = h.encode("123456789")
        h.verify("123456789", r)
        >>>>True


        To use, put this in any app and add to your settings.py, something like this:

        PASSWORD_HASHERS = (
            'django.contrib.auth.hashers.PBKDF2PasswordHasher',
            'myproject.myapp.usercake_hasher.UserCakePasswordHasher',
            'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
            'django.contrib.auth.hashers.BCryptPasswordHasher',
            'django.contrib.auth.hashers.SHA1PasswordHasher',
            'django.contrib.auth.hashers.MD5PasswordHasher',
            'django.contrib.auth.hashers.CryptPasswordHasher',
        )

    """
    algorithm = "usercake"

    def _apply_hash(self, salt, password):
        return hashlib.sha1( salt + password ).hexdigest()

    def _mask_hash(self, hash, show=6, char="*"):
        """
        Returns the given hash, with only the first ``show`` number shown. The
        rest are masked with ``char`` for security reasons.
        """
        masked = hash[:show]
        masked += char * len(hash[show:])
        return masked

    def salt(self):
        return get_random_string(25)

    def encode(self, password, salt=None):
        if not salt:
            salt = self.salt()

        assert len(salt) == 25

        encoded_hash =  self._apply_hash(salt, password)

        return self.algorithm + "$" + salt + encoded_hash

    def verify(self, password, encoded):
        algorithm, encoded = encoded.split("$", 1)
        assert algorithm == self.algorithm

        encoded_salt = encoded[:25]
        encoded_pass = encoded[25:]

        password_hash = self._apply_hash(encoded_salt, password)

        return password_hash == encoded_pass

    def safe_summary(self, encoded):
        algorithm, encoded = encoded.split("$", 1)
        assert algorithm == self.algorithm

        encoded_salt = encoded[:25]
        encoded_pass = encoded[25:]

        return OrderedDict([
            (_('algorithm'), self.algorithm),
            (_('iterations'), "0"),
            (_('salt'), self._mask_hash( encoded_salt )),
            (_('hash'), self._mask_hash( encoded_pass )),
        ])

    def must_update(self, encoded):
        """
        Forces usercake passwords to be updated to a more secure algorithm
        """
        algorithm, encoded = encoded.split("$", 1)
        if algorithm == self.algorithm:
            return True
        return False




