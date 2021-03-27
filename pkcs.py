#  Licensed under the General Public License, Version 3.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      https://www.gnu.org/licenses/gpl-3.0.en.html
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Contains all functions related to encrypting, decrypting, 
signing and verifying messages using rsa 
See https://en.wikipedia.org/wiki/RSA_(cryptosystem) for more info"""


import math
import random
import hashlib
import warnings

from prime import get_primes

from pem import (
    load_pem_priv, load_pem_pub,
    save_pem_priv, save_pem_pub
)

from common import (
    byte_size, bytes2int, 
    modular_inv, int2bytes
)

from exceptions import (
    VerificationError, DecryptionError, 
    KeyGenerationError, KeyReadError
)

from padding import (
    pad_for_encryption, pad_for_signing
)

from blinding import (
    get_blinding_factor, blinded_operation
)

__all__ = [
    "get_key_strength",
    "private2public",
    "AbstractKey",
    "PrivateKey",
    "PublicKey",
    "newkeys",
    "encrypt",
    "decrypt",
    "verify",
    "sign"
]


class AbstractKey:
    """Base class for RSA public and private keys
    :param p: A large prime number
    :param q: A large prime number"""
    def __init__(self, p: int, q: int) -> None:
        self.p = p
        self.q = q
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)

        # the default value for e is always set to 65537
        self.e = 65537  

        # if the modulus is less than 65537, e is set to 3
        if self.n < 65537:
            self.e = 3

        self.d = modular_inv(self.e, self.phi)
        self.dp = self.d % (self.p - 1)
        self.dq = self.d % (self.q - 1)
        self.qinv = modular_inv(self.q, self.p)

    def generate(self, directory, file) -> tuple:
        """Generates an RSA public or private key
        :param directory: Location of file
        :param file: File name
        :return: key data"""


class PublicKey(AbstractKey):
    """RSA public key class
    :param p: A large prime number
    :param q: A large prime number"""
    def __init__(self, p, q) -> None:
        super().__init__(p, q)
        
    def generate(self, directory, file="PUBLIC_KEY.pem") -> tuple:
        """Generates a RSA public key containing a tuple (n, e)
        where e is the public exponent and n is the modulus.
        :param directory: File path
        :param file: File name
        :return: key data"""
        save_pem_pub(n=self.n, e=self.e, path=directory, file=file)
        return self.n, self.e
        

class PrivateKey(AbstractKey):
    """RSA private key class
    :param p: A large prime number
    :param q: A large prime number"""
    def __init__(self, p, q) -> None:
        super().__init__(p, q)

    def generate(self, directory, file="PRIVATE_KEY.pem") -> tuple:
        """Generates a RSA private key.
        :param directory: File path
        :param file: File name
        :return: key data"""
        save_pem_priv(
            n=self.n, e=self.e, 
            d=self.d, p=self.p,
            q=self.q, dp=self.dp, 
            dq=self.dq, qinv=self.qinv,
            path=directory, file=file
        )
        
        return (
            self.n, self.e, self.d, self.p,
            self.q, self.dp, self.dq, self.qinv
        )


def newkeys(strength: int,  directory: str, pub_name="PUBLIC_KEY.pem", 
            pri_name="PRIVATE_KEY.pem") -> tuple:
    """Generates new RSA keys which have a modulus of ``strength`` bits in length
    :param pub_name: Name of the public key
    :param pri_name: Name of the private key
    :param strength: key strength
    :param directory: File location
    :return: Private key data"""
    # warn the user if the strength is less than 1024 bits
    if strength < 1024:
        warnings.warn("WARNING: The key strength is too low")

    # raise an exception because a key size less than 512 bits is unacceptable
    if strength < 512:
        raise KeyGenerationError("The key strength is too low")

    p, q = get_primes(strength)
    PublicKey(p, q).generate(directory, pub_name)
    data = PrivateKey(p, q).generate(directory, pri_name)

    return data


def encrypt(message, directory, file="PUBLIC_KEY.pem") -> bytes:
    """Encrypt a byte string
    :param message: Byte string containing the plain text message
    :param directory: Location of the public key
    :param file: Public key file name
    :return: A byte string containing the encrypted message"""
    # load a pem encoded public key
    _, n, e = load_pem_pub(path=directory, file=file)

    # find the byte size of modulus
    nbytes = byte_size(n)

    # pad and encrypt the message
    int_m = bytes2int(pad_for_encryption(message, nbytes))
    encrypted = pow(int_m, e, n)
    encrypted = int2bytes(encrypted, nbytes)

    return encrypted


def decrypt(c, directory, blinded=True, file="PRIVATE_KEY.pem") -> bytes:
    """Decrypt a byte string
    :param c: Byte string containing the cipher text
    :param directory: Location of the public key
    :param blinded: Use blinding if set to ``True``, if not, use CRT
    :param file: Private key file name
    :return: A byte string containing the decrypted message"""
    # load the pem encoded private key
    _, n, e, d, p, q, dp, dq, qinv = load_pem_priv(directory, file)

    nbytes = byte_size(n)  
    int_c = bytes2int(c)

    # use the Chinese Remainder Theorem if blinding is turned off
    if not blinded:
        m1 = pow(int_c, dp, p)
        m2 = pow(int_c, dq, q)
        h = (qinv * (m1 - m2)) % p
        decrypted = m2 + h * q

    # decrypt using blinding if blinding is turned off
    elif blinded:
        decrypted = blinded_operation(int_c, n, e, d)
        
    else:
        raise DecryptionError("Invalid argument {}".format(blinded))
        
    # convert the decrypted int to bytes
    decrypted = int2bytes(decrypted, nbytes)    

    # the \x00\x02 bytes must be present
    if decrypted[0:2] != b"\x00\002":
        raise DecryptionError("Decryption failed because clear text "
                              "markers are not present")
    
    # the byte length of the decrypted message must be equal to that of the modulus
    elif nbytes != len(decrypted):
        raise DecryptionError("Decryption failed because the byte "
                              "length of the modulus not equal to "
                              "that of the cipher text")
    
    # the \x00 separator must be present
    elif b"\x00" not in decrypted:
        raise DecryptionError("Decryption failed because \\x00 "
                              "separator not present")
    
    return decrypted[decrypted.index(b"\x00", 2) + 1:]


def sign(m: bytes, directory: str, hash=hashlib.sha256, file="PRIVATE_KEY.pem") -> bytes:
    """Sign the message using the private key
    :param m: The message to be signed
    :param directory: Location of RSA private key
    :param hash: Hashing algorithm
    :param file: File name of RSA private key 
    :return: The signed message"""
    # hash the message
    mhash = hash(m).hexdigest()

    # read the private key
    _, n, e, d, p, q, dp, dq, qinv = load_pem_priv(directory, file)

    # find the byte size of n
    nbytes = byte_size(n)

    # pad and encrypt the message
    int_m = bytes2int(pad_for_signing(bytes(mhash, "ascii"), nbytes))
    encrypted = blinded_operation(int_m, n, e, d)
    encrypted = int2bytes(encrypted, nbytes)

    return encrypted


def verify(s, m, directory, hash=hashlib.sha256, file="PUBLIC_KEY.pem"):
    """Verify the signature using the public key
    :param s: The signature
    :param m: The message
    :param directory: Location of public key
    :param hash: Hash algorithm to be used
    :param file: Name of public key
    :return: ``True`` if the signature is verified and ``False`` if otherwise"""
    _, n, e = load_pem_pub(directory, file)  # load the pem encoded public key

    # decrypt the message
    nbytes = byte_size(n)
    int_s = bytes2int(s)
    decrypted_s = pow(int_s, e, n)
    decrypted_s = int2bytes(decrypted_s, nbytes)

    # the \x00\x01 bytes must be present
    if decrypted_s[0:2] != b"\x00\001":
        raise VerificationError("Verification failed because clear text "
                                "markers are not present")
    
    # the byte length of the decrypted message must be equal to that of the modulus
    elif nbytes != len(decrypted_s):
        raise VerificationError("Verification failed because the byte "
                                "length of the modulus not equal to "
                                "that of the cipher text")
    
    # the \x00 separator must be present
    elif b"\x00" not in decrypted_s:
        raise VerificationError("Verification failed because \\x00 "
                                "separator not present")
    
    # we only read data after the 00 separator
    decrypted_s = decrypted_s[decrypted_s.index(b"\x00", 2) + 1:]  

    hashed_m = bytes(hash(m).hexdigest(), "ascii")  # hash the message

    # compare the decrypted signature and the hash
    if hashed_m == decrypted_s:
        return True
    else:
        return False


def get_key_strength(directory, keytype="public", name="PUBLIC_KEY.pem"):
    """Reads a key and returns the key's strength, i.e., the bit length of the modulus
    :param directory: The location of key
    :param keytype: If you want to read the modulus from the public key,
                    set this to ``"public"``, else, set this to ``"private"``
    :param name: the name of the public or private key"""
    if keytype == "public":
        data = load_pem_pub(directory, name)

    elif keytype == "private":
        data = load_pem_priv(directory, name)

    else: 
        raise KeyReadError("{} is not a valid key type".format(keytype))

    return data[1].bit_length()
    

def private2public(directory, write=True, pub_key_name="PUBLIC_KEY.pem", 
                   priv_key_name="PRIVATE_KEY.pem"):
    """Read a private key and return the public key
    :param directory: The directory containing the private key
    :param write: Write the data to a file if set to True, else just return n and e
    :param pub_key_name: Write data to this file if write is turned on
    :param priv_key_name: Read data from this file
    :return: Public key data"""
    # read the modulus and public exponent from the private key
    _, n, e, _, _, _, _, _, _ = load_pem_priv(directory, priv_key_name)

    # if write is set to False, return n and e
    if not write:
        return n, e

    # if write is set to True, write the data to a file and return n and e
    if write:
        save_pem_pub(n, e, directory, pub_key_name)
        return n, e
