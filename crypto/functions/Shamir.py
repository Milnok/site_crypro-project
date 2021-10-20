import random
from crypto.functions.Algoritms import evkl, Gen_prime, modinv, exp_mod


def Shamir_gen():
    p = Gen_prime(10 ** 100)
    cA = 0
    cB = 0
    dA = 0
    dB = 0
    flag = 1
    while flag == 1:
        cA = random.randint(0, p - 1)
        if evkl(cA, p - 1) == 1 and modinv(cA, p - 1) is not None:
            dA = modinv(cA, p - 1)
            flag = -1
    flag = 1
    while flag == 1:
        cB = random.randint(0, p - 1)
        if evkl(cB, p - 1) == 1 and modinv(cB, p - 1) is not None:
            dB = modinv(cB, p - 1)
            flag = -1
    return p, cA, cB, dA, dB


def ShamirShifr(text, p, cA, cB, dA, dB, file, filetype):
    if file:
        ifst = open(text, "rb").read()
        ofst = open("output." + filetype, "wb")
        text = ifst
    if not file:
        text1 = []
        for i in text:
            text1.append(ord(i))
        text = text1
    otv = ""
    p = int(p)
    cA = int(cA)
    cB = int(cB)
    dA = int(dA)
    dB = int(dB)
    for i in text:
        if i > p:
            return None
        x1 = exp_mod(i, cA, p)
        x2 = exp_mod(x1, cB, p)
        x3 = exp_mod(x2, dA, p)
        if file:
            ofst.write(bytes([exp_mod(x3, dB, p)]))
        if not file:
            otv += chr(exp_mod(x3, dB, p))
    if file:
        ofst = open("shifr.txt", "w")
        ofst.write(otv)
    if not file:
        return otv
