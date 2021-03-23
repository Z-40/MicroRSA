MicroRSA is a lightweight and easy-to-use library for python which lets you use RSA encryption in your projects.

MicroRSA can perform all RSA operations such as encryption, decryption, signing and signature verification and can generate keys as large as 16384 bits quickly and accurately.


###### Key generation time:
- 512 bit: 1/4 second
- 1024 bit: 1/2 second
- 2048 bit: 1 seconds
- 4096 bit: 5 seconds
- 8192 bit: 1 minute
- 16384 bit: 10 minutes


###### How to create new keys:
You can easily create RSA keys using the `newkeys()` function. 

    >>> import MicroRSA as rsa
    >>> rsa.newkeys(4096, "C:")

Here, 4096 is the key strength and `"C:"` is the directory in which to save the keys.


###### How to encrypt/decrypt data: 
You can encrypt data using the `encrypt()` function.

    >>> import MicroRSA as rsa
    >>> plaintext = b"THE ANSWER IS NO"
    >>> crypto = encrypt(plaintext, "C:")


To decrypt the cipher text, use the `decrypt()` function.

    >>> import MicroRSA as rsa
    >>> plaintext = b"THE ANSWER IS NO"
    >>> crypto = encrypt(plaintext, "C:")
    >>> decrypt(crypto, "C:")
    b"THE ANSWER IS NO"

`plaintext` is the data we want to encrypt and `crypto` is the cipher text (Both `plaintext` and `crypto` must be byte strings) 
and `"C:"` is the directory where the RSA keypair is stored.


