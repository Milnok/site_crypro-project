from django.shortcuts import render
from django.http import HttpResponse
from crypto.functions.RSA import RSA_gen_PQE, RSA_gen, RSA_shifr, RSA_deshifr
from crypto.functions.Diffie_Hellman import Diffie_Hellman_gen_P_G, Diffie_Hellman_gen
from crypto.functions.Shamir import Shamir_gen, ShamirShifr
from crypto.functions.ElGamal import ElGamal_Shifr, ElGamal_RasShifr


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
                asd, request.session['r'] = ElGamal_Shifr('media\\' + request.POST['ShifrFile'], int(request.session['g']),
                              int(request.session['Yb']), int(request.session['p']), True)
                filetype = request.POST['ShifrFile'].split(".")[-1]
                ElGamal_RasShifr('media\\' + request.POST['ShifrFile'], int(request.session['r']), int(request.session['p']), int(request.session['Xb']), True, filetype)
                Return['success'] = 'Файл удачно зашифрован и расшифрован'
        except:
            for field in fields:
                Return[field] = request.session[field]
            Return['error'] = 'Ошибка'
            return render(request, 'crypto/Elgamal.html', Return)
        for field in fields:
            Return[field] = request.session[field]
        return render(request, 'crypto/Elgamal.html', Return)
