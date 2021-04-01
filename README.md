MicroRSA is a lightweight and easy-to-use library for python which lets you use RSA encryption in your projects.

MicroRSA can perform all RSA operations such as encryption, decryption, signing and signature verification and can generate keys as large as 16384 bits quickly and accurately.
***

## Prerequisites: 
Before using MicroRSA in your projects, I recommend that you get a basic idea 
of how RSA works, please check out the [RSA wiki](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) to learn more.

## How to install:
To install the latest version, run this from the command line:

    pip install u-micro-rsa==2021.1

## Key generation time:
- 512 bit: 1/4 second*
- 1024 bit: 1/2 second*
- 2048 bit: 1 seconds*
- 4096 bit: 5 seconds*
- 8192 bit: 1 minute*
- 16384 bit: 10 minutes*

*These are approximate values, actual key generation time
may depend on your PC specs

## How to use:
### Creating new keys:
You can easily create RSA keys using the `newkeys()` function. 

    >>> import micro_rsa
    >>> micro_rsa.newkeys(4096, "C:")

Here, 4096 is the key strength and `"C:"` is the directory in which to save the keys.

### Encrypting/decrypting data: 
You can encrypt data using the `encrypt()` function.

    >>> import micro_rsa
    >>> plaintext = b"THE ANSWER IS NO!"
    >>> crypto = micro_rsa.encrypt(plaintext, "C:")

To decrypt the cipher text, use the `decrypt()` function.

    >>> import micro_rsa
    >>> plaintext = b"THE ANSWER IS NO!"
    >>> crypto = micro_rsa.encrypt(plaintext, "C:")
    >>> micro_rsa.decrypt(crypto, "C:")
    b"THE ANSWER IS NO!"

`plaintext` is the data we want to encrypt and `crypto` is the cipher text (Both `plaintext` and `crypto` must be byte strings) 
and `"C:"` is the directory where the RSA keypair is stored.

### Signing data and verifying signatures:
You can get the signature of the data using the `sign()` function.

    >>> import micro_rsa
    >>> data = b"Just some text I want to sign"
    >>> singnature = micro_rsa.sign(data, "C:")

To verify the signature, use the `verify()` function.

    >>> import micro_rsa
    >>> data = b"Just some text I want to sign"
    >>> signature = micro_rsa.sign(data, "C:")
    >>> micro_rsa.verify(signature, data, "C:")
    True

Here, `data` is the plain text we want to sign and `signature` is the rsa signature 
and `"C:"` is the directory that contains thr rsa keypair.

### Finding the strength of your RSA keys;
The `get_key_strength()` function can be used to do this

    >>> import micro_rsa
    >>> micro_rsa.get_key_strength("C:")
    >>> 16384

Just as before, `"C:"` is the directory that contains the RSA keypair.

### Deriving the public key from the private key
This can done using `private2pub()` function

    >>> import micro_rsa
    >>> data = micro_rsa.private2pub("C:", write=False)

If `write` is set to `False`, the function will only return the public key data,
however, if `write` is set to `True`, the function will return the key data and write the data 
to a file.
