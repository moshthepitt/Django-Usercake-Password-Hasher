Django Usercake Password Hasher
===============================

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

-----------------------------

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
