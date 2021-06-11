# Version 2021.2 - released 2021-4-2.
- The `newkeys()` function returns RSA key objects instead of writing the keys to files.
- You can save RSA keys as files using the `write_file()` method of RSA public and private key objects.
- To load the RSA key file you can use the `load_public_key()` function for public keys
and the `load_private_key()` function for the private keys

# Version 2021.3 - released 2021-4-3.
- Added LICENSE

# Version 2021.4 - released 2021-4-3.
- Added CHANGELOG
- Added README

# Version 2021.5 - released 2021-6-11.
- Make class `AbstractKey` a child class of `abc.ABC`
- Classes `PrivateKey` and `PublicKey` now both have `save_key` instead of `save_public_key` and `save_private_key`

I would like to thank @MorowyKomandos from the official python community on discord for the ideas


