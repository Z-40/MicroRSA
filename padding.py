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

"""Contains all functions related to padding messages before signing 
and encryption, for more information see https://en.wikipedia.org/wiki/
Padding_(cryptography)#:~:text=In%20cryptography%2C%20padding%20is%20
any,a%20message%20prior%20to%20encryption."""


import os
from micro_rsa.exceptions import PaddingError


def pad_for_encryption(m: bytes, dlen: int) -> bytes:
    """Pads a string m with random bytes for encryption 
    :param m: String to pad 
    :param dlen: Desired length of padded string
    :return: The padded message"""
    mlen = len(m)
    max_len = dlen - 11

    if mlen > max_len:
        raise PaddingError("Message can only fit {} bytes".format(max_len))

    padding_length = dlen - mlen - 3
    padding = b""

    while len(padding) < padding_length:
        needed_bytes = padding_length - len(padding)
        new_padding = os.urandom(padding_length).replace(b"\x00", b"")
        padding += new_padding[:needed_bytes]

    return b"".join((b"\x00\x02", padding, b"\x00", m))   


def pad_for_signing(m: bytes, dlen: int) -> bytes:
    """Pads a string m with random bytes for encryption 
    Padding for signing is different because it is a repetition of ff bytes
    :param m: String to pad 
    :param dlen: Desired length of padded string
    :return: The padded message"""
    mlen = len(m)
    max_len = dlen - 11

    if mlen > max_len:
        raise PaddingError("Message can only fit {} bytes".format(max_len))

    padding_length = dlen - mlen - 3

    return b"".join((
        b"\x00\x01", b"\xff" * padding_length, 
        b"\x00", m
    ))   
