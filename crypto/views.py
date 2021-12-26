from django.shortcuts import render
from django.http import HttpResponse
from crypto.functions.RSA import RSA_gen_PQE, RSA_gen, RSA_shifr, RSA_deshifr
from crypto.functions.Diffie_Hellman import Diffie_Hellman_gen_P_G, Diffie_Hellman_gen
from crypto.functions.Shamir import Shamir_gen, ShamirShifr
from crypto.functions.ElGamal import ElGamal_Shifr, ElGamal_RasShifr
from crypto.functions.MD5 import MD5_hash
from crypto.functions.SHA import SHA_hash
from crypto.functions.hashRSA import RSA_hash_step1, RSA_hash_step2
from crypto.functions.hashELGamal import hash_ELGamal_step1, hash_ELGamal_step2, hash_ELGamal_genXY


def home(request):
    return render(request, 'crypto/home.html')


def RSA(request):
    if request.method == 'GET':
        return render(request, 'crypto/RSA.html')
    else:
        fields = ('p', 'q', 'e', 'open', 'secret', 'n', 'text1', 'text2', 'text3')
        Return = {}
        try:
            for field in fields:
                request.session[field] = request.POST[field]

            if request.POST['submit'] == 'Random':
                request.session['p'], request.session['q'], request.session['e'] = RSA_gen_PQE()
            elif request.POST['submit'] == 'Create':
                request.session['open'], request.session['secret'], request.session['n'] = RSA_gen(request.session['p'],
                                                                                                   request.session['q'],
                                                                                                   request.session['e'])
            elif request.POST['submit'] == 'Shifr':
                request.session['text2'] = RSA_shifr(request.session['text1'], int(request.session['e']),
                                                     int(request.session['n']), None)

            elif request.POST['submit'] == 'Rasshifr':
                request.session['text3'] = RSA_deshifr(request.session['text2'], int(request.session['secret']),
                                                       int(request.session['n']), None, None)
            elif request.POST['submit'] == 'ShifrFile':
                RSA_shifr('media\\' + request.POST['ShifrFile'], int(request.session['e']),
                          int(request.session['n']), True)
                filetype = request.POST['ShifrFile'].split(".")[-1]
                RSA_deshifr(request.session['text2'], int(request.session['secret']),
                            int(request.session['n']), filetype, True)
                Return['success'] = 'Файл удачно зашифрован и расшифрован'
        except:
            for field in fields:
                Return[field] = request.session[field]
            Return['error'] = 'Ошибка'
            return render(request, 'crypto/RSA.html', Return)
    for field in fields:
        Return[field] = request.session[field]
    return render(request, 'crypto/RSA.html', Return)


def Diffie_hellman(request):
    if request.method == 'GET':
        return render(request, 'crypto/Diffie_hellman.html')
    else:
        fields = ('p', 'g', 'Xa', 'Ya', 'Xb', 'Yb', 'KeyA', 'KeyB')
        try:
            for field in fields:
                request.session[field] = request.POST[field]

            if request.POST['submit'] == 'GenPG':
                request.session['p'], request.session['g'] = Diffie_Hellman_gen_P_G()
            elif request.POST['submit'] == 'GetKey':
                request.session['KeyA'], request.session['KeyB'], request.session['Xa'], request.session['Xb'], \
                request.session['Ya'], request.session['Yb'] = Diffie_Hellman_gen(
                    int(request.POST['p']),
                    int(request.POST['g']))
        except:
            Return = {}
            for field in fields:
                Return[field] = request.session[field]
            Return['error'] = 'Ошибка'
            return render(request, 'crypto/Diffie_hellman.html', Return)
        Return = {}
        for field in fields:
            Return[field] = request.session[field]
        return render(request, 'crypto/Diffie_hellman.html', Return)


def Shamir(request):
    if request.method == 'GET':
        return render(request, 'crypto/Shamir.html')
    else:
        fields = ('p', 'cA', 'dA', 'cB', 'dB', 'text1', 'text2')
        try:
            for field in fields:
                request.session[field] = request.POST[field]

            if request.POST['submit'] == 'Gen':
                request.session['p'], request.session['cA'], request.session['cB'], request.session['dA'], \
                request.session['dB'] = Shamir_gen()
            elif request.POST['submit'] == 'Shifr':
                request.session['text2'] = ShamirShifr(request.POST['text1'], request.POST['p'], request.POST['cA'],
                                                       request.POST['cB'], request.POST['dA'], request.POST['dB'], None,
                                                       None)
        except:
            return render(request, 'crypto/Shamir.html')
        Return = {}
        for field in fields:
            Return[field] = request.session[field]
        return render(request, 'crypto/Shamir.html', Return)


def Elgamal(request):
    if request.method == 'GET':
        return render(request, 'crypto/Elgamal.html')
    else:
        fields = ('p', 'g', 'Xa', 'Ya', 'Xb', 'Yb', 'r', 'text1', 'text2', 'text3')
        Return = {}
        try:
            for field in fields:
                request.session[field] = request.POST[field]
            if request.POST['submit'] == 'GenPG':
                request.session['p'], request.session['g'] = Diffie_Hellman_gen_P_G()
            elif request.POST['submit'] == 'GetKey':
                asd1, asd, request.session['Xa'], request.session['Xb'], \
                request.session['Ya'], request.session['Yb'] = Diffie_Hellman_gen(
                    int(request.POST['p']),
                    int(request.POST['g']))
            elif request.POST['submit'] == 'Shifr':
                request.session['text2'], request.session['r'] = ElGamal_Shifr(request.session['text1'],
                                                                               int(request.session['g']),
                                                                               int(request.session['Yb']),
                                                                               int(request.session['p']), False)
            elif request.POST['submit'] == 'Rasshifr':
                request.session['text3'] = ElGamal_RasShifr(request.session['text2'], int(request.session['r']),
                                                            int(request.session['p']), int(request.session['Xb']),
                                                            False,
                                                            None)
            elif request.POST['submit'] == 'ShifrFile':
                asd, request.session['r'] = ElGamal_Shifr('media\\' + request.POST['ShifrFile'],
                                                          int(request.session['g']),
                                                          int(request.session['Yb']), int(request.session['p']), True)
                filetype = request.POST['ShifrFile'].split(".")[-1]
                ElGamal_RasShifr('media\\' + request.POST['ShifrFile'], int(request.session['r']),
                                 int(request.session['p']), int(request.session['Xb']), True, filetype)
                Return['success'] = 'Файл удачно зашифрован и расшифрован'
        except:
            for field in fields:
                Return[field] = request.session[field]
            Return['error'] = 'Ошибка'
            return render(request, 'crypto/Elgamal.html', Return)
        for field in fields:
            Return[field] = request.session[field]
        return render(request, 'crypto/Elgamal.html', Return)


def MD5(request):
    if request.method == 'GET':
        return render(request, 'crypto/MD5.html')
    else:
        fields = ('HashOne', 'text1', 'text2')
        Return = {}
        for field in fields:
            request.session[field] = request.POST[field]
        try:
            if request.POST['submit'] == 'Hash':
                request.session['HashOne'] = MD5_hash(request.session['text1'], False)
                request.session['text2'] = request.session['HashOne'] + '\n' + request.session['text2']
            elif request.POST['submit'] == 'HashFile':
                request.session['HashOne'] = MD5_hash('media\\' + request.POST['HashFile'], True)
                request.session['text2'] = request.session['HashOne'] + '\n' + request.session['text2']
        except:
            return render(request, 'crypto/MD5.html', Return)
    for field in fields:
        Return[field] = request.session[field]
    return render(request, 'crypto/MD5.html', Return)


def SHA(request):
    if request.method == 'GET':
        return render(request, 'crypto/SHA.html')
    else:
        fields = ('HashOne', 'text1', 'text2')
        Return = {}
        for field in fields:
            request.session[field] = request.POST[field]
        try:
            if request.POST['submit'] == 'Hash':
                request.session['HashOne'] = SHA_hash(request.session['text1'], False)
                request.session['text2'] = request.session['HashOne'] + '\n' + request.session['text2']
            elif request.POST['submit'] == 'HashFile':
                request.session['HashOne'] = SHA_hash('media\\' + request.POST['HashFile'], True)
                request.session['text2'] = request.session['HashOne'] + '\n' + request.session['text2']
        except:
            return render(request, 'crypto/SHA.html', Return)
    for field in fields:
        Return[field] = request.session[field]
    return render(request, 'crypto/SHA.html', Return)


def hashRSA(request):
    if request.method == 'GET':
        return render(request, 'crypto/hashRSA.html')
    else:
        fields = ('p', 'q', 'e', 'open', 'secret', 'n', 'text1', 'hash', 's', 'w')
        Return = {}
        try:
            for field in fields:
                request.session[field] = request.POST[field]

            if request.POST['submit'] == 'Random':
                request.session['p'], request.session['q'], request.session['e'] = RSA_gen_PQE()
            elif request.POST['submit'] == 'Create':
                request.session['open'], request.session['secret'], request.session['n'] = RSA_gen(request.session['p'],
                                                                                                   request.session['q'],
                                                                                                   request.session['e'])
            elif request.POST['submit'] == 'FindS':
                request.session['s'], request.session['hash'] = RSA_hash_step1(request.session['text1'],
                                                                               int(request.session['secret']),
                                                                               int(request.session['n']), False)
            elif request.POST['submit'] == 'FindW':
                request.session['w'], none = RSA_hash_step2(request.session['text1'],
                                                            int(request.session['s']), int(request.session['e']),
                                                            int(request.session['n']), False)
            elif request.POST['submit'] == 'IsEqual':
                if request.session['hash'] == request.session['w']:
                    Return['equal'] = 'Равны'
                else:
                    Return['notequal'] = 'Не равны'
            elif request.POST['submit'] == 'FileS':
                request.session['s'], request.session['hash'] = RSA_hash_step1('media\\' + request.POST['FileS'],
                                                                               int(request.session['secret']),
                                                                               int(request.session['n']), True)
            elif request.POST['submit'] == 'FileW':
                request.session['w'], none = RSA_hash_step2('media\\' + request.POST['FileW'],
                                                            int(request.session['s']), int(request.session['e']),
                                                            int(request.session['n']), True)

        except:
            for field in fields:
                Return[field] = request.session[field]
            Return['error'] = 'Ошибка'
            return render(request, 'crypto/hashRSA.html', Return)
    for field in fields:
        Return[field] = request.session[field]
    return render(request, 'crypto/hashRSA.html', Return)


def hashELGamal(request):
    if request.method == 'GET':
        return render(request, 'crypto/hashELGamal.html')
    else:
        fields = ('p', 'g', 'open', 'secret', 'text1', 'r', 's', 'left', 'right')
        Return = {}
        try:
            for field in fields:
                request.session[field] = request.POST[field]
            if request.POST['submit'] == 'GenPG':
                request.session['p'], request.session['g'] = Diffie_Hellman_gen_P_G()
            elif request.POST['submit'] == 'GetKey':
                request.session['secret'], request.session['open'] = hash_ELGamal_genXY(int(request.session['p']),
                                                                                        int(request.session['g']))
            elif request.POST['submit'] == 'FindRS':
                request.session['r'], request.session['s'] = hash_ELGamal_step1(request.session['text1'],
                                                                                int(request.session['secret']),
                                                                                int(request.session['open']),
                                                                                int(request.session['p']),
                                                                                int(request.session['g']), False)
            elif request.POST['submit'] == 'Send':
                boolean, request.session['left'], request.session['right'] = hash_ELGamal_step2(
                    request.session['text1'],
                    int(request.session['open']),
                    int(request.session['p']),
                    int(request.session['g']),
                    int(request.session['r']),
                    int(request.session['s']), False)
                if boolean:
                    Return['equal'] = 'Равны'
                elif not boolean:
                    Return['notequal'] = 'Не равны'

            elif request.POST['submit'] == 'FileRS':
                request.session['r'], request.session['s'] = hash_ELGamal_step1('media\\' + request.POST['FileRS'],
                                                                                int(request.session['secret']),
                                                                                int(request.session['open']),
                                                                                int(request.session['p']),
                                                                                int(request.session['g']), True)
            elif request.POST['submit'] == 'FileSend':
                boolean, request.session['left'], request.session['right'] = hash_ELGamal_step2(
                    'media\\' + request.POST['FileSend'],
                    int(request.session['open']),
                    int(request.session['p']),
                    int(request.session['g']),
                    int(request.session['r']),
                    int(request.session['s']), True)
                if boolean:
                    Return['equal'] = 'Равны'
                elif not boolean:
                    Return['notequal'] = 'Не равны'

        except:
            for field in fields:
                Return[field] = request.session[field]
            Return['error'] = 'Ошибка'
            return render(request, 'crypto/hashELGamal.html', Return)
    for field in fields:
        Return[field] = request.session[field]
    return render(request, 'crypto/hashELGamal.html', Return)
