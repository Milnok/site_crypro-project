import random
from crypto.functions.Algoritms import evkl, exp_mod, modinv, Is_prime, Gen_prime


def RSA_gen_PQE():
    p = Gen_prime(10**100)
    q = Gen_prime(10**100)
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


def RSA_shifr(text, e, n, file):
    if file:
        ifst = open(text, "rb").read()
        text = ifst
    if not file:
        text1 = []
        for i in text:
            text1.append(ord(i))
        text = text1
    otv = ""
    for i in text:
        if i > n:
            return None
        otv += str(exp_mod(i, e, n)) + " "
    otv = otv[:-1]
    if file:
        ofst = open("media\\shifr.txt", "w")
        ofst.write(otv)
        return True
    if not file:
        return otv


def RSA_deshifr(text, d, n, filetype, file):
    if file:
        ifst = open("media\\shifr.txt", "r").read()
        ofst = open("media\\output." + filetype, "wb")
        text = ifst
    chisla = text.split(" ")
    otv = ""
    for i in chisla:
        if file:
            ofst.write(bytes([exp_mod(int(i), d, n)]))
        if not file:
            otv += chr(exp_mod(int(i), d, n))
    if not file:
        return otv
