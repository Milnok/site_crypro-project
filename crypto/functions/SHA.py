text1 = 'md5'


def Func1(X, Y, Z):
    return (X & Y) | (~X & Z)


def Func2(X, Y, Z):
    return X ^ Y ^ Z


def Func3(X, Y, Z):
    return (X & Y) | (X & Z) | (Y & Z)


def Sdvig(x, n):
    return (x << n) | (x >> (32 - n))


def to_bit(text: str):
    otv = ''
    text = text.encode()
    for i in text:
        otv += bin(i)[2:].zfill(8)
    return otv


def add_length(text, file):
    bit_text = ''
    if file:
        ifst = open(text, 'rb').read()
        for i in ifst:
            bit_text += bin(i)[2:].zfill(8)
    else:
        bit_text = to_bit(text)
    bit_strk = bit_text + '1'
    while len(bit_strk) % 512 != 448:
        bit_strk += '0'
    bit_strk += bin(len(bit_text))[2:].zfill(64)
    return bit_strk


def bit512_to_list_int(block512):
    res = []
    for i in range(len(block512) // 32):
        res.append(int(block512[:32], 2))
        block512 = block512[32:]
    return res


def obrabotka_512block(one_block, A0, B0, C0, D0, E0):
    A, B, C, D, E = A0, B0, C0, D0, E0
    W = [0 for w in range(80)]
    for k in range(80):
        if 0 <= k <= 15:
            W[k] = one_block[k]
        if 16 <= k <= 79:
            W[k] = Sdvig((W[k - 3] ^ W[k - 8] ^ W[k - 14] ^ W[k - 16]), 1) % pow(2, 32)
    for j in range(4 * 20):
        if 0 <= j <= 19:
            k = 0x5A827999
            temp = Func1(B, C, D)
        elif 20 <= j <= 39:
            k = 0x6ED9EBA1
            temp = Func2(B, C, D)
        elif 40 <= j <= 59:
            k = 0x8F1BBCDC
            temp = Func3(B, C, D)
        elif 60 <= j <= 79:
            k = 0xCA62C1D6
            temp = Func2(B, C, D)

        temp = (Sdvig(A, 5) + temp) % pow(2, 32)
        temp = (temp + E) % pow(2, 32)
        temp = (temp + k) % pow(2, 32)
        temp = (temp + W[j]) % pow(2, 32)
        E = D
        D = C
        C = Sdvig(B, 30) % pow(2, 32)
        B = A
        A = temp

    A = (A0 + A) % pow(2, 32)
    B = (B0 + B) % pow(2, 32)
    C = (C0 + C) % pow(2, 32)
    D = (D0 + D) % pow(2, 32)
    E = (E0 + E) % pow(2, 32)

    return A, B, C, D, E


def obrabotka_texta(int_list):
    A0 = 0x67452301
    B0 = 0xEFCDAB89
    C0 = 0x98BADCFE
    D0 = 0x10325476
    E0 = 0xC3D2E1F0
    A, B, C, D, E = A0, B0, C0, D0, E0
    for one_block in int_list:
        A, B, C, D, E = obrabotka_512block(one_block, A, B, C, D, E)
    try:
        return A, B, C, D, E
    except:
        return None


def SHA_hash(text, file: bool):
    int_list = []
    bit_strk = add_length(text, file)
    for i in range(len(bit_strk) // 512):
        int_list.append(bit512_to_list_int(bit_strk[i * 512:(i + 1) * 512]))
    A, B, C, D, E = obrabotka_texta(int_list)
    res = bin(A)[2:].zfill(32)
    res += bin(B)[2:].zfill(32)
    res += bin(C)[2:].zfill(32)
    res += bin(D)[2:].zfill(32)
    res += bin(E)[2:].zfill(32)
    otv = ''
    for i in range(len(res)//4):
        otv += str(hex(int(res[:4],2)))[2:]
        res = res[4:]

    return otv

if __name__ == '__main__':
    print(SHA_hash('Text.txt', True))
    print(SHA_hash(text1, False))
