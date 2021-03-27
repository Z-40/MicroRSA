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

"""Contains all functions related to using blinding for signing and
decrypting using RSA, for more information on blinding see:
https://en.wikipedia.org/wiki/Blinding_(cryptography)"""

import math
from common import get_rand_num, modular_inv


def get_blinding_factor(n):
    """Get blinding factors r and r_inverse where r is approximately ``n``
    bits in length and r and n are relatively prime"""
    while True:
        r = get_rand_num(n - 1)
        if math.gcd(r, n) == 1:
            break

    r_inv = modular_inv(r, n)

    return r, r_inv


def blinded_operation(c, n, e, d):
    """Decrypt or sign a message using to blinding prevent side channel attacks
    See: https://en.wikipedia.org/wiki/Side-channel_attack"""
    b, binv = get_blinding_factor(n)
    blinded = (pow(b, e, n) * c) % n

    return (pow(blinded, d, n) * binv) % n
