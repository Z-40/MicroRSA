import base64
import exceptions
import pyasn1.type.univ as univ
import pyasn1.type.namedtype as namedtype
import pyasn1.codec.der.encoder as encoder
import pyasn1.codec.der.decoder as decoder


class PubKey(univ.Sequence):
    """RSA public key structure"""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("modulus", univ.Integer()),
        namedtype.NamedType("publicExponent", univ.Integer()),
    )


class PrivKey(univ.Sequence):
    """RSA private key structure"""
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


def save_pem_priv(n, e, d, p, q, dp, dq, qInv, path, file="PRIVATE_KEY.pem"):
    """
    Save a pem encoded private key
    :param n: Modulus
    :param e: Public Exponent
    :param d: Private Exponent
    :param p: prime1
    :param q: prime2
    :param dp: exp1
    :param dq: exp2
    :param qinv: q inverse
    :param path: Location to save the file
    :param file: File name
    """
    template = "-----BEGIN RSA PRIVATE KEY-----\n{}-----END RSA PRIVATE KEY-----"
    names = (
        "version",
        "modulus", 
        "publicExponent", 
        "privateExponent", 
        "prime1", 
        "prime2", 
        "exponent1", 
        "exponent2", 
        "coefficient"
    )
    seq = PrivKey()
    for i, x in enumerate((0, n, e, d, p, q, dp, dq, qInv)):
        seq.setComponentByName(names[i], univ.Integer(x))

    # encode the sequence and insert into the template
    der = encoder.encode(seq)
    b64 = base64.encodebytes(der).decode("ascii")
    final_data = template.format(b64)

    try:
        with open("{}\{}".format(path, file), "wb") as f:
            f.write(bytes(final_data, "ascii"))

    except:
        raise exceptions.KeyGenerationError("Could not write file to {}".format(path))

def save_pem_pub(n, e, path, file="PUBLIC_KEY.pem"):
    """
    Save a pem encoded private key
    :param n: Modulus
    :param e: Public Exponent
    :param path: Location to save the file
    :param file: File name
    """
    template = "-----BEGIN RSA PUBLIC KEY-----\n{}-----END RSA PUBLIC KEY-----"
    names = ("version", "modulus", "publicExponent")
    seq = PubKey()

    for i, x in enumerate((0, n, e)):
        seq.setComponentByName(names[i], univ.Integer(x))

    # encode the sequence and insert into the template
    der = encoder.encode(seq)
    b64 = base64.encodebytes(der).decode("ascii")
    final_data = template.format(b64)

    try:
        with open("{}\{}".format(path, file), "wb") as f:
            f.write(bytes(final_data, "ascii"))

    except:
        raise exceptions.KeyGenerationError("Could not write file to {}".format(path))


def load_pem_pub(path, file="PUBLIC_KEY.pem"):
    """
    Load a pem encoded public key
    :param path: Location of file
    :param file: File name
    """
    names = ("version", "modulus", "publicExponent")

    try:
        with open("{}\{}".format(path, file), "rb") as f:
            raw_data = f.read()

    except:
        raise exceptions.KeyReadError("Could not find file at {}".format(path))
    
    # remove the unwanted data
    data1 = raw_data.replace(b"-----BEGIN RSA PUBLIC KEY-----", b"")
    data2 = data1.replace(b"-----END RSA PUBLIC KEY-----", b"")
    data3 = data2.replace(b"\n", b"")

    # decode the base64 data
    try:
        der = base64.decodebytes(data3)
        decoded = decoder.decode(der, asn1Spec=PubKey())[0]

    except:
        raise exceptions.KeyReadError("Could not decode file")

    # get the values from the sequence and add them to the list
    values = []
    for i in range(3):
        values.append(int(decoded.getComponentByName(names[i])))

    return tuple(values)


def load_pem_priv(path, file="PRIVATE_KEY.pem"):
    """
    Load a pem encoded private key
    :param path: Location of file
    :param file: File name
    """
    names = (
        "version", 
        "modulus", 
        "publicExponent", 
        "privateExponent", 
        "prime1", 
        "prime2", 
        "exponent1", 
        "exponent2", 
        "coefficient"
    )

    try:
        with open("{}\{}".format(path, file), "rb") as f:
            raw_data = f.read()

    except:
        raise exceptions.KeyReadError("Could not find file at {}".format(path))

    # remove the unwanted data
    data1 = raw_data.replace(b"-----BEGIN RSA PRIVATE KEY-----", b"")
    data2 = data1.replace(b"-----END RSA PRIVATE KEY-----", b"")
    data3 = data2.replace(b"\n", b"")

    # decode the base64 data
    try:
        der = base64.decodebytes(data3)
        decoded = decoder.decode(der, asn1Spec=PrivKey())[0]
    
    except:
        raise exceptions.KeyReadError("Could not decode file")

    # get the values from the sequence and add them to the list
    values = []
    for i in range(9):
        values.append(int(decoded.getComponentByName(names[i])))

    return tuple(values)
