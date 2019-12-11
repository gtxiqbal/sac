from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.sessions.models import Session
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.conf import settings
from django.core.mail import send_mail
from auto_tl1.models import UserActive, UserTg
from auto_tl1.views import check_permissions
from random import randint
import requests
import random

# Create your views here.
def get_client_ip(request):
    X_FORWARDED_FOR = request.META.get('HTTP_X_FORWARDED_FOR')
    if X_FORWARDED_FOR:
        ip = X_FORWARDED_FOR.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')

    return ip

def randomString(stringLength):
    data_token = []
    for x in range(stringLength):
        data_token.append(random.randint(1, 101))

    #untuk kode token string
    #letters = string.ascii_letters
    #return f''.join(random.choice(letters) for i in range(stringLength))

    data_str = [str(x) for x in data_token]
    return ''.join(data_str)

def token_api(request, user, tipe):
    cekuser = UserTg.objects.filter(auth_user__username=user).count()

    if cekuser > 0:
        usertg = UserTg.objects.get(auth_user__username=user)

        token = randomString(3)
        request.session['token_api'] = token
        token = request.session['token_api']

        if tipe == 'Telegram':
            param_api = {
                'chat_id': usertg.id_chat,
                'text': f'Login username : {usertg.auth_user.username}\nIP : {get_client_ip(request)}\nKode OTP : {token}',
            }

            requests.get('https://api.telegram.org/bot632868473:AAEXzt269R43aG-bDpNYn4jMfPB4kstY7Qg/sendmessage', params=param_api)

        else:
            subject = 'Kode OTP APP WOC'
            message = f'Login username : {usertg.auth_user.username}\nIP : {get_client_ip(request)}\nKode OTP : {token}'
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [usertg.auth_user.email]
            send_mail(subject, message, email_from, recipient_list)

        return token
    else:
        return 'failed'

def formLogin(request):
    if request.user.is_authenticated:

        return redirect('auto_tl1:home')

    else:
        if 'username' in request.session:
            del request.session['username']
            del request.session['password']

            if request.session.modified == False:
                del request.session['token_api']

        context = {
            'page_title' : 'Login to Apps'
        }

        request.session['captcha1'] = randint(1, 5)
        request.session['captcha2'] = randint(1, 5)

        return render(request, 'login.html', context)

def formPilihOTP(request):
    if request.method == "POST":
        request.session['username'] = request.POST['username']
        request.session['password'] = request.POST['password']

        captcha1 = request.session['captcha1']
        captcha2 = request.session['captcha2']

        if int(request.POST['capctha']) != captcha1 + captcha2:
            messages.add_message(request, messages.INFO, 'Captcha tidak sesuai')
            del request.session['captcha1']
            del request.session['captcha2']

            return redirect('login:formlogin')

    if 'username' not in request.session and 'password' not in request.session and request.user.is_anonymous:
        return redirect('login:formlogin')
    elif 'username' not in request.session and 'password' not in request.session and not request.user.is_anonymous:
        pass

    return render(request, 'choiceotp.html')

def pilihOTP(request, tipe):
    if 'captcha1' in request.session and 'captcha2' in request.session:
        if request.session == False:
            del request.session['captcha1']
            del request.session['captcha2']

    if tipe is not None:
        request.session['tipe'] = tipe

    return redirect('login:getToken')

def getToken(request):
    username = request.session['username'] if 'username' in request.session else request.user.username
    tipe = request.session['tipe'] if 'tipe' in request.session else 'Telegram'

    if token_api(request, username, tipe) == 'failed':
        messages.add_message(request, messages.INFO, 'ID Chat atau Username belum terdaftar')
        del request.session['username']
        del request.session['password']

        return redirect('login:formlogin')

    if request.session.modified == False:
        del request.session['tipe']

    messages.add_message(request, messages.INFO, f'OTP sudah dikirim ke {tipe}')

    return redirect('login:formtoken')


def formToken(request):
    if request.user.is_anonymous:
        if 'username' not in request.session:
            return redirect('login:formlogin')

    context = {
        'page_title': 'Masukkan Token'
    }

    username = request.session['username'] if 'username' in request.session else request.user.username

    if 'api_token' in request.session and request.user.is_authenticated:
        return redirect('auto_tl1:home')

    if 'token_api' not in request.session:
        token = token_api(request, username)
        if token == 'failed':
            messages.add_message(request, messages.INFO, 'ID Chat belum terdaftar')
            return redirect('login:proses_logout')

    if request.is_ajax():
        usertg = UserTg.objects.get(auth_user__username=username)
        token = request.session['token_api']

        if request.POST['tipe'] == 'Telegram':
            param_api = {
                'chat_id': usertg.id_chat,
                'text': f'Login username : {username}\nIP : {get_client_ip(request)}\nKode OTP : {token}',
            }

            req = requests.get('https://api.telegram.org/bot632868473:AAEXzt269R43aG-bDpNYn4jMfPB4kstY7Qg/sendmessage', params=param_api)

            datas = {
                'tipe' : 'Telegram',
                'status' : req.status_code,
                'data' : req.json()
            }
        else:
            subject = 'Kode OTP APP WOC'
            message = f'Login username : {usertg.auth_user.username}\nIP : {get_client_ip(request)}\nKode OTP : {token}'
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [usertg.auth_user.email]
            send_mail(subject, message, email_from, recipient_list)
            datas = {
                'tipe': 'Email',
                'data': usertg.auth_user.email
            }

        json_data = JsonResponse(datas)

        return json_data


    return render(request, 'formtoken.html', context)

def cekToken(request):
    if request.method == "POST":
        if request.session['token_api'] == request.POST['token_api']:

            if request.user.is_authenticated:
                request.session['api_token'] = request.session['token_api']
                return redirect('auto_tl1:home')

            return redirect('login:proses_login')
        else:
            messages.add_message(request, messages.INFO, 'Token yang anda masukkan salah')
            return redirect('login:formtoken')

def loginView(request):
    if 'token_api' in request.session:
        username_login = request.session['username']
        password_login = request.session['password']

        user = authenticate(request, username=username_login, password=password_login)
        try:
            if user is not None:
                login(request, user)
                request.session['api_token'] = request.session['token_api']
                return redirect('auto_tl1:home')
            else:
                messages.add_message(request, messages.INFO, 'Username atau Password salah')
        except Exception as e:
            messages.add_message(request, messages.INFO, f'Ada error saat login {e}: ')
        return redirect('login:formlogin')

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
def logoutView(request):
    if request.is_ajax():
        if request.POST['sessionid'] == request.COOKIES['sessionid']:
            logout(request)

            return JsonResponse({'status': 'ok'})

    elif request.method == 'POST':
        if 'logout' in request.POST:
            logout(request)

            return redirect('login:formlogin')

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
def terminate(request):
    if request.method == 'POST':
        sessionid = request.POST['sessionid']
        check_user_session  = Session.objects.filter(session_key=sessionid).count()

        if check_user_session > 0:
            s = Session.objects.get(session_key=sessionid)
            s.delete()
        else:
            user_active = UserActive.objects.get(sessionid=sessionid)
            user_active.delete()

        return JsonResponse({'status' : True})

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
@user_passes_test(check_permissions)
def flushSession(request):
    if request.is_ajax():
        user_aktif = UserActive.objects.all()

        for aktif in user_aktif:
            sesi = Session.objects.exclude(session_key=aktif.sessionid)
            sesi.delete()

        return JsonResponse({'status' : True})