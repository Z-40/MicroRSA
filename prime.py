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

"""Contains all functions related to finding large primes for generating
RSA public and private keys"""

import math
import random

from MicroRSA.common import modular_inv
from MicroRSA.sieve_base import sieve_base


def miller_rabin(n: int, k: int) -> bool:
    """
    Perform the rabin miller primality test
    :param n: Number to perform the test on
    :param k: Number of witnesses
    :return: True if the number is prime and Flase if composite
    """
    if n == 2:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def getprime(n: int, e=65537) -> int:
    """
    Find a strong prime ``n`` bits in length
    :param n: Desired bit length of number
    :param e: Public exponent
    :return: A prime number exactly ``n`` bits in length

    Based on the paper "Fast Generation of Random, Strong RSA primes"
    by Robert D. Silverman

    A copy of the document is available for download at:
    https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.17.2713&rep=rep1&type=pdf
    """
    x = (n - 512) >> 7

    lower_bound = lower_bound = divmod(
        (14142135623730950489) * ((2) ** (511 + 128 * x)),
        (10000000000000000000)
    )[0]

    upper_bound = (1 << (512 + 128*x)) - 1

    x = random.randrange(lower_bound, upper_bound)

    p = [0, 0]
    for i in (0, 1):
        y = random.getrandbits(101)
        field = [0] * 5 * len(sieve_base)
        for prime in sieve_base:
            for j in range((prime - y % prime) % prime, len(field), prime):
                field[j] = 1

        result = 0
        for j in range(len(field)):
            composite = field[j]

            if composite:
                continue
            
            tmp = y + j
            result = miller_rabin(tmp, 25)
            
            if result > 0:
                p[i] = tmp
                break
        
        if result == 0:
            pass

    r = modular_inv(p[1], p[0]) * p[1] - \
        modular_inv(p[0], p[1]) * p[0]

    increment = p[0] * p[1]
    x += r - (x % increment)
    while 1:
        is_possible_prime = 1
        for prime in sieve_base:
            if (x % prime) == 0:
                is_possible_prime = 0
                break

        if e and is_possible_prime:
            if e & 1:
                if math.gcd(e, x - 1) != 1:
                    is_possible_prime = 0
            else:
                if math.gcd(e, divmod((x - 1), 2)[0]) != 1:
                    is_possible_prime = 0

        if is_possible_prime:
            result = miller_rabin(x, 25)

            if result > 0:
                break

        x += increment

        if x >= 1 << n:
            raise RuntimeError("Couln't find prime in field")
                               
    return x
        

def get_primes(blen: int, e:int) -> tuple:
    """
    Get two large primes
    :param blen: Intended bit length of modulus
    :param e: Public Exponent
    :return: Returns the values as a tuple
    """
    p = []
    for i in range(2):
        num = getprime(blen // 2, e)
        p.append(num)

    return p
