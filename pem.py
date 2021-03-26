# Copyright (C) 2021 Z-40

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

"""Contains all functions related to reading/writing
RSA public/private keys using Privacy Enhanced Mail (PEM)
See https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail for more info"""

import base64
import pyasn1.type.univ as univ
import pyasn1.type.namedtype as namedtype
import pyasn1.codec.der.encoder as encoder
import pyasn1.codec.der.decoder as decoder

from MicroRSA.exceptions import KeyGenerationError, KeyReadError


class PubKeySequence(univ.Sequence):
    """RSA public key structure
    RSAPrivateKey ::= SEQUENCE {
        version           Version,
        modulus           INTEGER,  -- n
        publicExponent    INTEGER,  -- e
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
    )


class PrivKeySequence(univ.Sequence):
    """RSA private key structure
        RSAPublicKey ::= SEQUENCE {
        modulus           INTEGER,  -- n
        publicExponent    INTEGER   -- e
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
        namedtype.NamedType("coefficient", univ.Integer()),
    )


def save_pem_priv(n, e, d, p, q, dp, dq, qinv, path, file="PRIVATE_KEY.pem"):
    """Save a pem encoded private key
    :param n: Modulus
    :param e: Public Exponent
    :param d: Private Exponent
    :param p: prime1
    :param q: prime2
    :param dp: exp1
    :param dq: exp2
    :param qinv: q inverse
    :param path: Location to save the file
    :param file: File name"""
    template = "-----BEGIN RSA PRIVATE KEY-----\n{}-----END RSA PRIVATE KEY-----"
    names = (
        "version", "modulus", "publicExponent", 
        "privateExponent", "prime1", "prime2", 
        "exponent1", "exponent2", "coefficient"
    )
    seq = PrivKeySequence()
    for i, x in enumerate((0, n, e, d, p, q, dp, dq, qinv)):
        seq.setComponentByName(names[i], univ.Integer(x))

    # encode the sequence and insert into the template
    der = encoder.encode(seq)
    b64 = base64.encodebytes(der).decode("ascii")
    final_data = template.format(b64)

    try:
        with open("{}\{}".format(path, file), "wb") as f:
            f.write(bytes(final_data, "ascii"))

    except PermissionError or FileExistsError:
        raise KeyGenerationError("Could not write file to {}".format(path))


def save_pem_pub(n, e, path, file="PUBLIC_KEY.pem"):
    """Save a pem encoded private key
    :param n: Modulus
    :param e: Public Exponent
    :param path: Location to save the file
    :param file: File name"""
    template = "-----BEGIN RSA PUBLIC KEY-----\n{}-----END RSA PUBLIC KEY-----"
    names = ("version", "modulus", "publicExponent")
    seq = PubKeySequence()

    for i, x in enumerate((0, n, e)):
        seq.setComponentByName(names[i], univ.Integer(x))

    # encode the sequence and insert into the template
    der = encoder.encode(seq)
    b64 = base64.encodebytes(der).decode("ascii")
    final_data = template.format(b64)

    try:
        with open("{}\{}".format(path, file), "wb") as f:
            f.write(bytes(final_data, "ascii"))

    except PermissionError or FileExistsError:
        raise KeyGenerationError("Could not write file to {}".format(path))


def load_pem_pub(path, file="PUBLIC_KEY.pem"):
    """Load a pem encoded public key
    :param path: Location of file
    :param file: File name"""
    names = ("version", "modulus", "publicExponent")

    try:
        with open("{}\{}".format(path, file), "rb") as f:
            raw_data = f.read()

    except FileNotFoundError:
        raise KeyReadError("Could not find file at {}".format(path))
    
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
    values = []
    for i in range(3):
        values.append(int(decoded.getComponentByName(names[i])))

    return tuple(values)


def load_pem_priv(path, file="PRIVATE_KEY.pem"):
    """Load a pem encoded private key
    :param path: Location of file
    :param file: File name"""
    names = (
        "version", "modulus", "publicExponent", 
        "privateExponent", "prime1", "prime2", 
        "exponent1", "exponent2", "coefficient"
    )

    try:
        with open("{}\{}".format(path, file), "rb") as f:
            raw_data = f.read()

    except FileNotFoundError:
        raise KeyReadError("Could not find file at {}".format(path))

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
    values = []
    for i in range(9):
        values.append(int(decoded.getComponentByName(names[i])))

    return tuple(values)
