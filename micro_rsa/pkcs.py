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

import base64
import pyasn1.type.univ as univ
import pyasn1.type.namedtype as namedtype
import pyasn1.codec.der.decoder as decoder
import pyasn1.codec.der.encoder as encoder

from micro_rsa.prime import get_primes

from micro_rsa.common import (
    byte_size, bytes2int,
    modular_inv, int2bytes
)

from micro_rsa.exceptions import (
    VerificationError, DecryptionError,
    KeyGenerationError, KeyReadError
)

from micro_rsa.padding import (
    pad_for_encryption, pad_for_signing
)

from micro_rsa.blinding import (
    get_blinding_factor, blinded_operation
)


hash_methods = {
        "MD5": hashlib.md5,
        "SHA-1": hashlib.sha1,
        "SHA-224": hashlib.sha224,
        "SHA-256": hashlib.sha256,
        "SHA-384": hashlib.sha384,
        "SHA-512": hashlib.sha512,
        "SHA3-224": hashlib.sha3_224,
        "SHA3-256": hashlib.sha3_256,
        "SHA3-384": hashlib.sha3_384,
        "SHA3-512": hashlib.sha3_512
}


class PubKeySequence(univ.Sequence):
    """RSA public key structure
    RSAPrivateKey ::= SEQUENCE {
        modulus           INTEGER,  -- n
        publicExponent    INTEGER,  -- e
    }"""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("modulus", univ.Integer()),
        namedtype.NamedType("publicExponent", univ.Integer())
    )


class PrivKeySequence(univ.Sequence):
    """RSA private key structure
    RSAPublicKey ::= SEQUENCE {
        version           Version,
        modulus           INTEGER,  -- n
        publicExponent    INTEGER   -- e
        privateExponent   INTEGER,  -- d
        prime1            INTEGER,  -- p
        prime2            INTEGER,  -- q
        exponent1         INTEGER,  -- d mod (p-1)
        exponent2         INTEGER,  -- d mod (q-1)
        coefficient       INTEGER,  -- (inverse of q) mod p
        otherPrimeInfos   OtherPrimeInfos OPTIONAL
    }"""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("modulus", univ.Integer()),
        namedtype.NamedType("publicExponent", univ.Integer()),
        namedtype.NamedType("privateExponent", univ.Integer()),
        namedtype.NamedType("prime1", univ.Integer()),
        namedtype.NamedType("prime2", univ.Integer()),
        namedtype.NamedType("exponent1", univ.Integer()),
        namedtype.NamedType("exponent2", univ.Integer()),
        namedtype.NamedType("coefficient", univ.Integer())
    )


class AbstractKey:
    """Base class for RSA public and private keys
    :param n: Key modulus
    :param e: Public exponent"""
    def __init__(self, n: int, e: int) -> None:
        self.n = n
        self.e = e

    def save_private_key(self, directory: str, file: str):
        """Save a pem encoded private key
        :param directory: Location to save the file
        :param file: filename of private key
        :return: None"""
        key_attributes = ("version", "modulus", "publicExponent",
                "privateExponent", "prime1", "prime2",
                "exponent1", "exponent2", "coefficient")
        key_values = (
            0, self.n, self.e, self.d, 
            self.p, self.q, self.dp, 
            self.dq, self.qinv
        )
        seq = PrivKeySequence()
        for i, x in enumerate(key_values):
            seq.setComponentByName(key_attributes[i], univ.Integer(x))

        # encode the sequence and insert into the template
        der = encoder.encode(seq)
        b64 = base64.encodebytes(der).decode("ascii")
        final_data = "-----BEGIN RSA PRIVATE KEY-----\n{}-----END RSA PRIVATE KEY-----" \
                     .format(b64)

        try:
            with open("{}\{}".format(directory, file), "wb") as f:
                f.write(bytes(final_data, "ascii"))

        except PermissionError or FileExistsError:
            raise KeyGenerationError("Could not write file to {}".format(directory))


    def save_public_key(self, directory: str, file: str):
        """Save a pem encoded private key
        :param directory: Location to save the file
        :param file: filename of the public key
        :return: None"""
        key_attributes = ("modulus", "publicExponent")

        seq = PubKeySequence()
        for i, x in enumerate((self.n, self.e)):
            seq.setComponentByName(key_attributes[i], univ.Integer(x))

        # encode the sequence and insert into the template
        der = encoder.encode(seq)
        b64 = base64.encodebytes(der).decode("ascii")
        final_data = "-----BEGIN RSA PUBLIC KEY-----\n{}-----END RSA PUBLIC KEY-----" \
                     .format(b64)

        try:
            with open("{}\{}".format(directory, file), "wb") as f:
                f.write(bytes(final_data, "ascii"))

        except PermissionError or FileExistsError:
            raise KeyGenerationError("Could not write file to {}".format(directory))


class PublicKey(AbstractKey):
    """RSA public key class
    :param n: Key modulus
    :param e: Public exponent"""
    def __init__(self, n: int, e: int) -> None:
        super().__init__(n, e)
        
    def write_file(self, directory: str, file: str) -> None:
        """Write the public key to a file
        :param directory: location to save the file
        :param file: filename of public key
        :return: None"""
        super().save_public_key(directory, file)
        

class PrivateKey(AbstractKey):
    """RSA private key class"""
    def __init__(self, n, e, d, p, q, dp, dq, qinv) -> None:
        super().__init__(n, e)
        self.d = d
        self.p = p
        self.q = q
        self.dp = dp
        self.dq = dq
        self.qinv = qinv
        
    def write_file(self, directory: str, file: str) -> tuple:
        """Generates a RSA private key.
        :param directory: File path
        :param file: File name
        :return: key data"""
        super().save_private_key(directory, file)


def calculate_key_values(p: int, q: int):
    """Calculate key values 
    :param p: prime1
    :param q: prime2
    :return: Dictionary containing key data"""
    n = p * q
    phi = (p - 1) * (q - 1)

    if n < 65537: e = 3
    else: e = 65537

    d = modular_inv(e, phi)
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = modular_inv(q, p)

    return {
        "modulus": n,
        "publicExponent": e,
        "privateExponent": d,
        "prime1": p,
        "prime2": q,
        "exponent1": dp,
        "exponent2": dq,
        "coefficient": qinv
    }


def newkeys(strength: int) -> tuple:
    """Generates new RSA keys which have a modulus of ``strength`` bits in length
    :param strength: desired key strength
    :return: RSA public and private key objects"""
    # warn the user if the strength is less than 1024 bits
    if strength < 1024:
        warnings.warn("WARNING: The key strength is too low")

    # raise an exception because a key size less than 512 bits is unacceptable
    if strength < 512:
        raise KeyGenerationError("The key strength is too low")

    # calculate the key values
    p, q = get_primes(strength)
    key_values = calculate_key_values(p, q)

    # create key objects
    public = PublicKey(key_values["modulus"], key_values["publicExponent"])
    private = PrivateKey(
        key_values["modulus"],
        key_values["publicExponent"],
        key_values["privateExponent"],
        key_values["prime1"],
        key_values["prime2"],
        key_values["exponent1"],
        key_values["exponent2"],
        key_values["coefficient"]
    )

    return public, private


def encrypt(message: bytes, key: PublicKey) -> bytes:
    """Encrypt a byte string
    :param message: Byte string containing the plain text message
    :param key: RSA public key object
    :return: A byte string containing the encrypted message"""
    nbytes = byte_size(key.n)

    # pad and encrypt the message
    int_m = bytes2int(pad_for_encryption(message, nbytes))
    encrypted = pow(int_m, key.e, key.n)
    encrypted = int2bytes(encrypted, nbytes)

    return encrypted


def decrypt(c: bytes, key: PrivateKey, blinded=True) -> bytes:
    """Decrypt a byte string
    :param c: Byte string containing the cipher text
    :param key: RSA private key object
    :param blinded: Use blinding if set to ``True``, if not, use CRT
    :return: A byte string containing the decrypted message
    
    NOTE: The decryption will be 2x faster if blinding is turned off, 
          but it can make it easier for attackers to use timing attacks"""
    nbytes = byte_size(key.n)
    int_c = bytes2int(c)

    # use the Chinese Remainder Theorem if blinding is turned off
    if not blinded:
        m1 = pow(int_c, key.dp, key.p)
        m2 = pow(int_c, key.dq, key.q)
        h = (key.qinv * (m1 - m2)) % key.p
        decrypted = m2 + h * key.q

    # decrypt using blinding if blinding is turned on
    elif blinded:
        decrypted = blinded_operation(int_c, key.n, key.e, key.d)
        
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
        raise DecryptionError("Decryption failed because 00 "
                              "separator not present")
    
    return decrypted[decrypted.index(b"\x00", 2) + 1:]


def sign(m: bytes, key: PrivateKey, hash_method="SHA-256") -> bytes:
    """Sign the message using the private key
    :param m: The message to be signed
    :param key: RSA private key object
    :param hash_method: Hashing algorithm
    :return: The signed message"""
    mhash = hash_methods[hash_method](m).hexdigest()
    nbytes = byte_size(key.n)

    # pad and encrypt the message
    int_m = bytes2int(pad_for_signing(bytes(mhash, "ascii"), nbytes))
    encrypted = blinded_operation(int_m, key.n, key.e, key.d)
    encrypted = int2bytes(encrypted, nbytes)

    return encrypted


def verify(m: bytes, s: bytes, key: PublicKey, hash_method="SHA-256"):
    """Verify the signature using the public key
    :param m: The message
    :param s: The signature
    :param key: RSA public key object
    :param hash_method: Hash algorithm to be used
    :return: ``True`` if the signature is verified and ``False`` if otherwise"""
    nbytes = byte_size(key.n)

    # verify
    int_s = bytes2int(s)
    decrypted_s = pow(int_s, key.e, key.n)
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

    # hash_method the message
    hashed_m = bytes(hash_methods[hash_method](m).hexdigest(), "ascii")

    # compare the decrypted signature and the hash_method
    if hashed_m == decrypted_s:
        return True
    else:
        return False


def get_key_strength(key):
    """Reads a key and returns the key's strength, 
    i.e., the bit length of the modulus
    :param key: RSA key object"""
    return key.n.bit_length()


def private2public(key: PrivateKey):
    """Read a private key and return the public key
    :param key: RSA private key object
    :return: RSA public key object"""
    return PublicKey(key.n, key.e)


def load_public_key(directory, file) -> PublicKey:
    """Load a pem encoded public key
    :param path: Location of file
    :param file: File name
    :return: A dictionary containing key data"""
    try:
        with open("{}\{}".format(directory, file), "rb") as f:
            raw_data = f.read()

    except FileNotFoundError:
        raise KeyReadError("Could not find file at {}".format(directory))
    
    # remove the unwanted data
    data1 = raw_data.replace(b"-----BEGIN RSA PUBLIC KEY-----", b"")
    data2 = data1.replace(b"-----END RSA PUBLIC KEY-----", b"")
    data3 = data2.replace(b"\n", b"")

    # decode the base64 data
    try:
        der = base64.decodebytes(data3)
        decoded = decoder.decode(der, asn1Spec=PubKeySequence())[0]

    except TypeError:
        raise KeyReadError("Could not decode file")

    # get the values from the sequence and add them to the list
    key_data = {"modulus": None, "publicExponent": None}
    for key in key_data.keys():
        key_data[key] = int(decoded.getComponentByName(key))

    return PublicKey(key_data["modulus"], key_data["publicExponent"])


def load_private_key(directory, file) -> PrivateKey:
    """Load a pem encoded private key
    :param path: Location of file
    :param file: File name
    :return: A dictionary containing key data"""
    try:
        with open("{}\{}".format(directory, file), "rb") as f:
            raw_data = f.read()

    except FileNotFoundError:
        raise KeyReadError("Could not find file at {}".format(directory))

    # remove the unwanted data
    data1 = raw_data.replace(b"-----BEGIN RSA PRIVATE KEY-----", b"")
    data2 = data1.replace(b"-----END RSA PRIVATE KEY-----", b"")
    data3 = data2.replace(b"\n", b"")

    # decode the base64 data
    try:
        der = base64.decodebytes(data3)
        decoded = decoder.decode(der, asn1Spec=PrivKeySequence())[0]
    
    except TypeError:
        raise KeyReadError("Could not decode file")

    # get the values from the sequence and add them to the list
    key_data = {"version": None,
                "modulus": None,
                "publicExponent": None,
                "privateExponent": None,
                "prime1": None,
                "prime2": None,
                "exponent1": None,
                "exponent2": None,
                "coefficient": None}
    for key in key_data.keys():
        key_data[key] = int(decoded.getComponentByName(key))

    return PrivateKey(
        key_data["modulus"],
        key_data["publicExponent"],
        key_data["privateExponent"],
        key_data["prime1"],
        key_data["prime2"],
        key_data["exponent1"],
        key_data["exponent2"],
        key_data["coefficient"]
    )
