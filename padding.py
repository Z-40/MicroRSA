import os
import exceptions


def pad_for_encryption(m: bytes, dlen: int) -> bytes:
    """
    Pads a string m with random bytes for encryption 
    :param m: String to pad 
    :param dlen: Desired length of padded string
    :return: A padded byte-string
    :return type: bytes
    """
    mlen = len(m)
    max_len = dlen - 11

    if mlen > max_len:
        raise exceptions.PaddingError("Message can only fit {} bytes".format(max_len))

    padding_length = dlen - mlen - 3
    padding = b""

    while len(padding) < padding_length:
        needed_bytes = padding_length - len(padding)
        new_padding = os.urandom(padding_length).replace(b"\x00", b"")
        padding += new_padding[:needed_bytes]

    return b"".join((b"\x00\x02", padding, b"\x00", m))   


def pad_for_signing(m: bytes, dlen: int) -> bytes:
    """
    Pads a string m with random bytes for encryption 
    Padding for signing is different because it is a repetition of ff bytes
    :param m: String to pad 
    :param dlen: Desited length of padded string
    :return: A padded byte-string
    :return type: bytes
    """
    mlen = len(m)
    max_len = dlen - 11

    if mlen > max_len:
        raise exceptions.PaddingError("Message can only fit {} bytes".format(max_len))

    padding_length = dlen - mlen - 3

    return b"".join((b"\x00\x01", b"\xff" * padding_length, b"\x00", bytes(m, "utf-8")))   
