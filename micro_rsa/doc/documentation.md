MicroRSA is a lightweight and easy-to-use library for python which lets you use RSA encryption in your projects.

MicroRSA can perform all RSA operations such as encryption, decryption, signing and signature verification and can generate keys as large as 16384 bits quickly and accurately.
***

## Prerequisites: 
Before using MicroRSA in your projects, I recommend that you get a basic idea 
of how RSA works, please check out the [RSA wiki](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) to learn more.

## How to install:
To install the latest version, run this from the command line:

    pip install u-micro-rsa

## Key generation time:
- 512 bit: 1/4 second*
- 1024 bit: 1/2 second*
- 2048 bit: 1 seconds*
- 4096 bit: 5 seconds*
- 8192 bit: 1 minute*
- 16384 bit: 10 minutes*

*These are approximate values, actual key generation time
may depend on your PC specs.

## How to use:
### Creating new keys:
You can easily create RSA keys using the `newkeys()` function. 

    >>> import micro_rsa
    >>> public, private = micro_rsa.newkeys(4096)

Here, 4096 is the key strength and `public` and `private` are the RSA 
public and private key objects.

### Encrypting/decrypting data: 
You can encrypt data using the `encrypt()` function.

    >>> import micro_rsa
    >>> public, private = micro_rsa.newkeys(4096)
    >>> plaintext = b"THE ANSWER IS NO!"
    >>> crypto = micro_rsa.encrypt(plaintext, public)

To decrypt the cipher text, use the `decrypt()` function.

    >>> import micro_rsa
    >>> public, private = micro_rsa.newkeys(4096)
    >>> plaintext = b"THE ANSWER IS NO!"
    >>> crypto = micro_rsa.encrypt(plaintext, public)
    >>> micro_rsa.decrypt(crypto, private)
    b"THE ANSWER IS NO!"

`plaintext` is the data we want to encrypt and `crypto` is the cipher text (Both `plaintext` and `crypto` must be byte strings) 
and `public` and `private` are the RSA key objects.

### Signing data and verifying signatures:
You can get the signature of the data using the `sign()` function.

    >>> import micro_rsa
    >>> public, private = micro_rsa.newkeys(4096)
    >>> data = b"Just some text I want to sign"
    >>> singnature = micro_rsa.sign(data, private)

To verify the signature, use the `verify()` function.

    >>> import micro_rsa
    >>> public, private = micro_rsa.newkeys(4096)
    >>> data = b"Just some text I want to sign"
    >>> signature = micro_rsa.sign(data, private)
    >>> micro_rsa.verify(data, signature, public)
    True

Here, `data` is the plain text we want to sign and `signature` is the rsa signature 
and `public` and `private` are the RSA key objects

### Finding the strength of your RSA keys;
The `get_key_strength()` function can be used to do this

    >>> import micro_rsa
    >>> public, private = micro_rsa.newkeys(16384)
    >>> micro_rsa.get_key_strength(public)
    >>> 16384

Just as before, `public` and `private` are the RSA key objects

### Deriving the public key from the private key
This can done using `private2pub()` function.

    >>> import micro_rsa
    >>> _, private = micro_rsa.newkeys(16384)
    >>> public = micro_rsa.private2pub(private)

### Saving the keypair
The RSA public and private keys can be saved as files by using the 
`write_file()` method.

    >>> import micro_rsa
    >>> public, private = micro_rsa.newkeys(16384)
    >>> public.write_file("D:", "public.key")

`D:` is the directory where the key is to be stored and `public.key`
is the file name for the public key file.

You can save the private key in the same way.

### Loading the keypair
The RSA public and private key files can be loaded using the `load_public_key()` function.

    >>> import micro_rsa
    >>> public = micro_rsa.load_public_key("D:", "public.key")

`D:` is the directory where the key is stored and `public.key`
is the file name for the public key file.

You can also load the private key using the `load_private_key()` function.
