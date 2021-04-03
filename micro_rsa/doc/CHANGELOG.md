# Version 2021.2 - released 2021-4-4.
- The `newkeys()` function returns RSA key objects instead of writing the keys to files.
- You can save RSA keys as files using the `write_file()` method of RSA public and private key objects.
- To load the RSA key file you can use the `load_public_key()` function for public keys
and the `load_private_key()` function for the private keys
