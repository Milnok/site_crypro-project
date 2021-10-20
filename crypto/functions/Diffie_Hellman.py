import random
from crypto.functions.Algoritms import evkl, exp_mod, modinv, Is_prime, Gen_prime
import time


def Diffie_Hellman_gen_P_G():
    start = time.time()
    flag = 1
    while 1 == 1:
        q = Gen_prime(pow(10,100))
        if Is_prime(2 * q + 1):
            print(time.time() - start)
            p = 2 * q + 1
            abc = 0
            while 1 == 1:
                abc += 1
                g = random.randint(0, p - 1)
                print(abc)
                if exp_mod(g, q, p) != 1:
                    print(time.time() - start)
                    return p, g


def Diffie_Hellman_gen(p, g):
    flag = 1
    Xa = 0
    Xb = 0
    try:
        p = int(p)
        g = int(g)
    except BaseException:
        return None, None
    Xa = Gen_prime(p)
    Xb = Gen_prime(p)
    Ya = exp_mod(g, Xa, p)
    Yb = exp_mod(g, Xb, p)

    Zab = exp_mod(Yb, Xa, p)

    Zba = exp_mod(Ya, Xb, p)
    return Zab, Zba, Xa, Xb, Ya, Yb
