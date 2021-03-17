import math
from MicroRSA.common import get_rand_num, modular_inv


def get_blinding_factor(n):
    """
    Get blinding factors r and r_inverse where r is approxmately ``n``
    bits in length and r and n are relatively prime
    """
    blindr = None
    while True:
        r = get_rand_num(n - 1)
        if math.gcd(r, n) == 1:
            blindr = r
            break

    blindr_inv = modular_inv(blindr, n)

    return blindr, blindr_inv


def blinded_operation(c, n, e, d):
    """
    Decrypt or sign a message using to blinding prevent side channel attacks
    See: https://en.wikipedia.org/wiki/Side-channel_attack
    """
    b, binv = get_blinding_factor(n)
    blinded = (pow(b, e, n) * c) % n

    return (pow(blinded, d, n) * binv) % n
