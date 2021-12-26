import random
from crypto.functions.Algoritms import evkl, exp_mod, modinv, Is_prime, Gen_prime
from crypto.functions.MD5 import MD5_hash


def RSA_gen_PQE():
    p = Gen_prime(10 ** 100)
    q = Gen_prime(10 ** 100)
    flag = 1
    while flag == 1:
        e = Gen_prime((p - 1) * (q - 1) - 1)
        if evkl((p - 1) * (q - 1), e):
            return p, q, e


def RSA_gen(p, q, e):
    if not Is_prime(int(p)) or not Is_prime(int(q)) or not Is_prime(int(e)):
        return None
    p, q, e = int(p), int(q), int(e)
    n = p * q
    fi = (p - 1) * (q - 1)
    if e > fi or n % e == 0:
        return None
    d = modinv(e, fi)
    if d is None:
        return None
    return e, d, n


def RSA_hash_step1(text: str, d, n, file: bool):
    hash_summ = 0
    if file:
        hash_summ = MD5_hash(text, True)
    if not file:
        hash_summ = MD5_hash(text, False)
    s = exp_mod(int(hash_summ, 16), d, n)
    return s, hash_summ


def RSA_hash_step2(text, s, e, n, file: bool):
    hash_summ = 0
    if file:
        hash_summ = MD5_hash(text, True)
    if not file:
        hash_summ = MD5_hash(text, False)
    w = exp_mod(s, e, n)

    return hex(w)[2:].zfill(32), hash_summ


if __name__ == '__main__':
    p, q, e = RSA_gen_PQE()
    e, d, n = RSA_gen(p, q, e)
    s = RSA_hash_step1('Привет', d, n, False)
    w, is_same = RSA_hash_step2('Привет', s, e, n, False)
    print(is_same)
