import random


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


def get_primes(blen: int) -> tuple:
    """
    Get two large primes
    :param blen: Intended bit length of modulus
    :return: Returns the values as a tuple 
    """
    p = []
    for i in range(2):
        while True:
            num = random.getrandbits(blen // 2)
            if miller_rabin(num, 10):
                p.append(num)
                break

    return tuple(p)
