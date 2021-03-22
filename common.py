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

"""Common functionality shared by several modules"""

import math
import random


def get_rand_num(maxvalue: int) -> int:
    """Find a random number which is approxmately ``maxvalue`` in length."""
    bit_size = maxvalue.bit_length()

    tries = 0
    while True:
        value = random.getrandbits(bit_size)
        if value <= maxvalue:
            break

        elif tries % 10 == 0 and tries:
            bit_size -= 1

        tries += 1

    return value


def egcd(a, b) -> tuple:
    """
    Perform the extended elucidean algorithm
    :param a: the first integer
    :param b: the second integer
    """
    x = 0
    y = 1
    lx = 1
    ly = 0
    oa = a  
    ob = b  
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    if lx < 0:
        lx += ob  
    if ly < 0:
        ly += oa  
    return a, lx, ly  


def modular_inv(a, m) -> int:
    """
    Find the modular multiplicative inverse of two numbers
    :param a: the first integer
    :param m: the second integer
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception("Modular inverse does not exist")
    else:
        return x % m


def byte_size(number: int) -> bytes:
    """
    Find the byte size of a number
    :parm number: The number to find the byte size of
    :return: The byte size of the number
    """
    quo, rem = divmod(number.bit_length(), 8)
    if rem:
        quo += 1

    return quo


def int2bytes(number: int, fill_size: int) -> bytes:
    """Convert an int to bytes"""
    if number < 0:
        raise ValueError("Number must be an unsigned integer: {}".format(number))

    bytes_required = max(1, math.ceil(number.bit_length() / 8))

    if fill_size > 0:
        return number.to_bytes(fill_size, "big")

    return number.to_bytes(bytes_required, "big")


def bytes2int(b, signed=False):
    """Convert bytes to an int"""
    return int.from_bytes(b, "big", signed=signed)


if __name__ == "__main__":
    pass
