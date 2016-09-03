# BCryptPasswordHasher

An alternative to django builtin `django.contrib.auth.hashers.BCryptPasswordHasher` that removes the unnecesary algorithm name prefix on every hashed value.

Given that it nows stick to the standard pattern `$modular_crypt_format$cost$hash_and_salt`, third party bcrypt clients, can understand the hashed value directly.

## How to use?

Update the `PASSWORD_HASHERS` value in your `settings.py` file to include this hasher as your first preferred hasher:

```python
PASSWORD_HASHERS = [
    'hashers.BcryptPasswordHasher',
    'django.contrib.auth.hashers.BCryptPasswordHasher',
]
```

And that's it! Django will take care of the rest :)

## How to contribute?

Provide some tests with your ideas and make sure that the current ones are still passing:

```sh
python test_hashers.py
```
