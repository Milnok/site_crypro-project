import random
from crypto.functions.Algoritms import evkl, Gen_prime, modinv, exp_mod, Is_prime


def ElGamal_Shifr(text, g, Db, p, file):
    if file:
        ifst = open(text, "rb").read()
        ofst = open("media\\shifr.txt", "w")
        text = ifst
    if not file:
        text1 = []
        for i in text:
            text1.append(ord(i))
        text = text1
    try:
        g = int(g)
        Db = int(Db)
        p = int(p)
    except BaseException:
        return None, None
    if not Is_prime(p):
        return None, None
    k = Gen_prime(p-3)
    e = ""
    for i in text:
        if int(i) > p:
            return None, None
        e += str((i * exp_mod(Db, k, p)) % p) + " "
    e = e[:-1]
    r = exp_mod(g, k, p)
    if file:
        ofst.write(e)
        return None, str(r)
    if not file:
        return e, str(r)


def ElGamal_RasShifr(text, r, p, Cb, file, filetype):
    if file:
        ifst = open("media\\shifr.txt", "r").read()
        ofst = open("media\\output." + filetype, "wb")
        text = ifst
    try:
        r = int(r)
        p = int(p)
        Cb = int(Cb)
    except BaseException:
        return None, None
    if not Is_prime(p):
        return None
    chisla = text.split(" ")
    otv = ""
    for i in chisla:
        if int(i) > p:
            return None
        if file:
            ofst.write(bytes([int(i) * (exp_mod(r, p - 1 - Cb, p)) % p]))
        if not file:
            otv += chr(int(i) * (exp_mod(r, p - 1 - Cb, p)) % p)
    if not file:
        return otv


