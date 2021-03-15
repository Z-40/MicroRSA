import common, math


def get_blinding_factor(n):
    """
    Get blinding factors r and r_inverse where r is approxmately ``n``
    bits in length and r and n are relatively prime
    """
    blindr = None
    while True:
        r = common.get_rand_num(n - 1)
        if math.gcd(r, n) == 1:
            blindr = r
            break

    blindr_inv = common.modular_inv(blindr, n)

    return blindr, blindr_inv


def blinded_operation(c, n, e, d):
    """Decrypt or sign a message using"""
    b, binv = get_blinding_factor(n)
    blinded = (pow(b, e, n) * c) % n

    return (pow(blinded, d, n) * binv) % n
