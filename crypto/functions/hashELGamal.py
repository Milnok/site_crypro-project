import random
from crypto.functions.Algoritms import evkl, exp_mod, modinv, Is_prime, Gen_prime
from crypto.functions.MD5 import MD5_hash
from crypto.functions.Diffie_Hellman import Diffie_Hellman_gen, Diffie_Hellman_gen_P_G


def hash_ELGamal_genXY(p, g):
    x = random.randint(1, p - 1)  # Секретный ключ
    y = exp_mod(g, x, p)  # Открытый ключ
    return x, y


def hash_ELGamal_step1(text, x, y, p, g, file):
    if file:
        hash_summ = MD5_hash(text, True)
    if not file:
        hash_summ = MD5_hash(text, False)
    if int(hash_summ, 16) >= p:
        return Exception
    k = random.randint(1, p - 1)
    while evkl(k, p - 1) != 1:
        k = random.randint(1, p - 1)
    r = exp_mod(g, k, p)
    u = (int(hash_summ, 16) - x * r) % (p - 1)
    s = (modinv(k, p - 1) * u) % (p - 1)
    return r, s


def hash_ELGamal_step2(text, y, p, g, r, s, file):
    if file:
        hash_summ = MD5_hash(text, True)
    if not file:
        hash_summ = MD5_hash(text, False)
    first_part = (exp_mod(y, r, p) * exp_mod(r, s, p)) % p
    second_part = exp_mod(g, int(hash_summ, 16), p)
    is_same = first_part == second_part
    return is_same, first_part, second_part


if __name__ == '__main__':
    p, g = Diffie_Hellman_gen_P_G()
    text = 'abcdc'
    x, y = hash_ELGamal_genXY(p, g)
    r, s = hash_ELGamal_step1(text, x, y, p, g, False)
    is_same, first_part, second_part = hash_ELGamal_step2(text, y, p, g, r, s, False)
    print(is_same)
