import requests
from django.shortcuts import render, redirect, HttpResponse
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.db.models import Count
from django.conf import settings
from auto_tl1.models import ServerTl1, GponDevice, LogTL1, UserActive, CmdTL1, Sto, LogApp
from auto_tl1.utils import render_to_pdf
from auto_tl1.serializers import GponSerializer
from socket import *
from datetime import datetime
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView
import paramiko
import time
import xlwt
import platform
import os
import numpy as np
# Create your views here.+

def cek_level(request):
    if 'api_token' in request.session:
        if request.user.is_superuser == True:
            request.session['level'] = 'superadmin'
        elif request.user.is_staff == True:
            request.session['level'] = 'admin'
        else:
            request.session['level'] = 'user'

        if request.session.modified == False:
            del request.session['api_token']
            del request.session['toke_api']
    else:
        request.session['level'] = 'zero'

    return request.session['level']

def check_permissions(user):
    if user.is_staff is True or user.is_superuser is True:
        return True

    return False

def get_client_ip(request):
    X_FORWARDED_FOR = request.META.get('HTTP_X_FORWARDED_FOR')
    if X_FORWARDED_FOR:
        ip = X_FORWARDED_FOR.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def session_login(request):
    cek_level(request)
    sessionid = request.COOKIES[settings.SESSION_COOKIE_NAME]
    check_user_active  = UserActive.objects.filter(sessionid=sessionid).count()
    if check_user_active > 0:
        user_active = UserActive.objects.get(sessionid=sessionid)
        user_active.ip_client = get_client_ip(request)
        user_active.level = request.session['level']
        user_active.save()
    else:
        UserActive.objects.create(sessionid=sessionid, username=request.user, ip_client=get_client_ip(request), level=request.session['level'], last_login=request.user.last_login)

    return cek_level(request)

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
def index(request):
    if session_login(request) == 'zero':
        return redirect('login:formOtp')

    vendor = ServerTl1.objects.values('vendor').order_by('vendor').annotate(vcount=Count('vendor'))
    all_device = GponDevice.objects.all()
    fh_device = GponDevice.objects.select_related('ip_server').filter(ip_server__vendor="fh")
    zte_device = GponDevice.objects.select_related('ip_server').filter(ip_server__vendor="zte")
    hw_device = GponDevice.objects.select_related('ip_server').filter(ip_server__vendor="hw")
    dataLog = LogTL1.objects.all().order_by('-time')[:10]
    context = {
        'all_devices' : len(all_device),
        'fh_device' : len(fh_device),
        'zte_device' : len(zte_device),
        'hw_device': len(hw_device),
        'page_title' : 'Home',
        'vendors' : vendor,
        'last_event' : dataLog,
        'client_ip' : get_client_ip(request),
    }

    return render(request, 'home.html', context)

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
def cekSN(request, cek_tipe, vendor_code):
    if session_login(request) == 'zero':
        return redirect('login:formOtp')
    if cek_tipe == 'unreg':
        page_title = 'Cek SN Unregister'
    elif cek_tipe == 'reg':
        page_title = 'Cek SN Register'
    elif cek_tipe == 'status':
        page_title = 'Cek Statu SN'
    elif cek_tipe == 'service':
        page_title = 'Cek Service ONT'

    vendor = ServerTl1.objects.values('vendor').order_by('vendor').annotate(vcount=Count('vendor'))
    server_tl1 = ServerTl1.objects.values('ip_server', 'name', 'id').filter(vendor=vendor_code).order_by('name')

    context = {
        'page_title' : page_title,
        'vendors' : vendor,
        'cek_tipe' : cek_tipe,
        'vendor_code' : vendor_code,
        'placeholder': 'contoh:\n172.x.x.x\n192.x.x.x\n10.x.x.x.x',
        'server_tl1': server_tl1,
        'client_ip': get_client_ip(request),
    }

    return render(request, 'formceksn.html', context)

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
def cekUnregSN(request, vendor_code):
    if session_login(request) == 'zero':
        return redirect('login:formOtp')

    page_title = 'Cek SN Unregister'

    if request.is_ajax():
        tl1 = ServerTl1.objects.get(ip_server=request.POST['tl1_server'])
        ip_server = tl1.ip_server
        port_tl1 = tl1.port_tl1

        datas = []
        pesan_param = 'No Unregister ONU'
        ip_gpon = request.POST['ip_gpon'].splitlines()

        target = f'IP NMS: {ip_server}'
        logApp = logAppIn(request, page_title, target)

        if vendor_code == "fh" or vendor_code == "zte":
            # connect tl1 via socket
            s = socket(AF_INET, SOCK_STREAM)
            s.connect((ip_server, port_tl1))

            if vendor_code == "fh":
                # login tl1 fiberhome
                cmd_login = f'LOGIN:::CTAG::UN={tl1.user_tl1},PWD={tl1.pass_tl1};'
                s.send(cmd_login.encode())
                time.sleep(2)

                for ip in ip_gpon:
                    log = LogTL1(target=ip, action=f"{page_title} FIBERHOME", command=ip, time=datetime.now(), status='In Progress', message='No Error', logapp=logApp)
                    log.save()

                    cmd = f'LST-UNREGONU::OLTID={ip}:CTAG::;'
                    tl1_cmd = tl1_command(s, cmd, datas, log, log.id, False, pesan_param)
                    if tl1_cmd['status'] == False:
                        logAppFailed(logApp.id)

                        return JsonResponse(
                            {
                                'status': tl1_cmd['status'],
                                'data': tl1_cmd['data']
                            }
                        )

                s.send(b'LOGOUT:::CTAG::;')
            else:
                for ip in ip_gpon:
                    log = LogTL1(target=ip, action=f"{page_title} ZTE", command=ip, time=datetime.now(), status='In Progress', message='No Error', logapp=logApp)
                    log.save()

                    cmd = f'LST-UNREGONU::OLTID={ip}:CTAG::;'
                    tl1_cmd = tl1_command(s, cmd, datas, log, log.id, pesan_param)
                    if tl1_cmd['status'] == False:
                        logAppFailed(logApp.id)
                         

                        return JsonResponse(
                            {
                                'status': tl1_cmd['status'],
                                'data': tl1_cmd['data']
                            }
                        )


            s.close()
            request.session['hw'] = False

        else:
            user_name = tl1.user_tl1
            passwd = tl1.pass_tl1
            ip_server = tl1.ip_server

            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            ip_gpon = request.POST['ip_gpon'].splitlines()
            ssh_client.connect(hostname=ip_server, username=user_name, password=passwd, look_for_keys=False)
            cmd_gpon = f"""{user_name}
{passwd}
enable
scroll

config
display ont autofind all
quit
quit
y

"""

            for ip in ip_gpon:
                datas.append(f'HOST : {ip}')
                command = f"telnet {ip}"
                stdin, stdout, stderr = ssh_client.exec_command(command)
                time.sleep(1)

                log = LogTL1(target=ip, action=f"{page_title} HUAWEI", command=ip, time=datetime.now(), status='In Progress', message='No Error', logapp=logApp)
                log.save()

                stdin.write(cmd_gpon)
                hasil = stdout.read().decode()
                cmd_tl1 = CmdTL1(command_tl1='display ont autofind all', logtl1=log, result_tl1=hasil)
                cmd_tl1.save()
                datas.append(hasil)

                log = LogTL1.objects.get(pk=log.id)
                log.stoptime = datetime.now()

                if 'Failure: The automatically found ONTs do not exist' in hasil:
                    status = 'Failed'
                    pesan = 'No Unregister ONU'

                elif '%Error ' in hasil:
                    status = 'Failed'
                    pesan = 'IP GPON must vendor HUAWEI'

                    log.status = status
                    log.message = pesan
                    log.save()

                    logAppFailed(logApp.id)

                    return JsonResponse(
                        {
                            'status': False,
                            'data': pesan
                        }
                    )

                else:
                    status = "Success"
                    pesan = 'No Error'

                log.status = status
                log.message = pesan
                log.save()

            ssh_client.exec_command("logout")
            ssh_client.close()
            request.session['hw'] = True

        logAppSuccess(logApp.id)

        datas = '\n'.join(datas)
        request.session['hasil'] = datas
        return JsonResponse(
            {
                'status' : True,
            }
        )

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
def cekRegSN(request, vendor_code):
    if session_login(request) == 'zero':
        return redirect('login:formOtp')

    page_title = 'Cek SN Register'
    if request.is_ajax():
        tl1 = ServerTl1.objects.get(ip_server=request.POST['tl1_server'])
        ip_server = tl1.ip_server
        port_tl1 = tl1.port_tl1

        datas = []
        pesan_param = 'No Register ONU'
        ip_gpon = request.POST['ip_gpon'].splitlines()

        target = f'IP NMS: {ip_server}'
        logApp = logAppIn(request, page_title, target)

        if vendor_code == "fh" or vendor_code == "zte":
            # connect tl1 via socket
            s = socket(AF_INET, SOCK_STREAM)
            s.connect((ip_server, port_tl1))

            if vendor_code == "fh":
                # login tl1 fiberhome
                cmd_login = f'LOGIN:::CTAG::UN={tl1.user_tl1},PWD={tl1.pass_tl1};'
                s.send(cmd_login.encode())
                time.sleep(2)

                for ips in ip_gpon:
                    ip = ips.split(';')
                    cmd = f'LST-ONU::OLTID={ip[0]}:CTAG::;'
                    time_sleep = 7
                    data_slot_port = ''

                    if len(ip) > 1:
                        cmd = f'LST-ONU::OLTID={ip[0]},PONID=1-1-{ip[1]}:CTAG::;'
                        slot_port = ip[1].split('-')
                        slot = slot_port[0]
                        port = slot_port[1]
                        data_slot_port = f', SLOT/PORT: {slot}/{port}'
                        time_sleep = 1

                    if len(ip) > 2:
                        cmd = f'LST-ONU::OLTID={ip[0]},PONID=1-1-{ip[1]},ONUIDTYPE=MAC,ONUID={ip[2]}:CTAG::;'
                        slot_port = ip[1].split('-')
                        slot = slot_port[0]
                        port = slot_port[1]
                        data_slot_port = f', SLOT/PORT: {slot}/{port}, SN: {ip[2]}'
                        time_sleep = 1

                    log = LogTL1(target=f"IP GPON: {ip[0]}{data_slot_port}", action=f"{page_title} FIBERHOME", command=ips, time=datetime.now(), status='In Progress', message='No Error', logapp=logApp)
                    log.save()

                    tl1_cmd = tl1_command(s, cmd, datas, log, log.id, False, pesan_param, time_sleep)
                    if tl1_cmd['status'] == False:
                        logAppFailed(logApp.id)

                        return JsonResponse(
                            {
                                'status': tl1_cmd['status'],
                                'data': tl1_cmd['data']
                            }
                        )

                s.send(b'LOGOUT:::CTAG::;')

            else:
                for ips in ip_gpon:
                    ip = ips.split(';')

                    cmd = f'LST-ONU::OLTID={ip[0]}:CTAG::;'
                    data_slot_port = ''
                    time_sleep = 7

                    if len(ip) > 1:
                        cmd = f'LST-ONU::OLTID={ip[0]},PONID=1-1-{ip[1]}:CTAG::;'
                        slot_port = ip[1].split('-')
                        slot = slot_port[0]
                        port = slot_port[1]
                        data_slot_port = f', SLOT/PORT: {slot}/{port}'
                        time_sleep = 1

                    if len(ip) > 2:
                        cmd = f'LST-ONU::OLTID={ip[0]},PONID=1-1-{ip[1]},ONUIDTYPE=SN,ONUID={ip[2]}:CTAG::;'
                        slot_port = ip[1].split('-')
                        slot = slot_port[0]
                        port = slot_port[1]
                        data_slot_port = f', SLOT/PORT: {slot}/{port}, SN: {ip[2]}'
                        time_sleep = 1

                    log = LogTL1(target=f"IP GPON: {ip[0]}{data_slot_port}", action=f"{page_title} ZTE", command=ips, time=datetime.now(), status='In Progress', message='No Error', logapp=logApp)
                    log.save()

                    tl1_cmd = tl1_command(s, cmd, datas, log, log.id, pesan_param, time_sleep)
                    if tl1_cmd['status'] == False:
                        logAppFailed(logApp.id)

                        return JsonResponse(
                            {
                                'status': tl1_cmd['status'],
                                'data': tl1_cmd['data']
                            }
                        )

            s.close()
            request.session['hw'] = False
        else:
            user_name = tl1.user_tl1
            passwd = tl1.pass_tl1
            ip_server = tl1.ip_server

            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            ip_gpon = request.POST['ip_gpon'].splitlines()

            ssh_client.connect(hostname=ip_server, username=user_name, password=passwd)

            for ips_gpon in ip_gpon:
                ip = ips_gpon.split(';')
                sn = ip[1]
                datas.append(f'HOST : {ip[0]}, SN : {sn}')
                command = f"telnet {ip[0]}"
                cmd_gpon = f"""{user_name}
{passwd}
enable
scroll

display ont info by-sn {sn}


quit
y

"""
                stdin, stdout, stderr = ssh_client.exec_command(command)
                time.sleep(1)

                log = LogTL1(target=f'IP GPON: {ip[0]}, SN: {sn}', action=f"{page_title} HUAWEI", command=ip, time=datetime.now(), status='In Progress', message='No Error', logapp=logApp)
                log.save()

                stdin.write(cmd_gpon)
                hasil = stdout.read().decode()
                cmd_tl1 = CmdTL1(command_tl1='display ont autofind all', logtl1=log, result_tl1=hasil)
                cmd_tl1.save()
                datas.append(hasil)

                log = LogTL1.objects.get(pk=log.id)
                log.stoptime = datetime.now()

                if 'The required ONT does not exist' in hasil:
                    status = 'Failed'
                    pesan = 'No Register ONU'

                elif 'Incomplete command, the error locates at' in hasil:
                    status = 'Failed'
                    pesan = 'Format is wrong'
                    
                else:
                    status = "Success"
                    pesan = 'No Error'

                log.status = status
                log.message = pesan
                log.save()

                ssh_client.exec_command("logout")
                ssh_client.close()
                request.session['hw'] = True

        datas = '\n'.join(datas)
        request.session['hasil'] = datas

        logAppSuccess(logApp.id)

        return JsonResponse(
            {
                'status': True,
            }
        )

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
def cekStatusSN(request, vendor_code):
    if session_login(request) == 'zero':
        return redirect('login:formOtp')

    page_title = 'Cek Status SN'
    if request.is_ajax():
        tl1 = ServerTl1.objects.get(ip_server=request.POST['tl1_server'])
        ip_server = tl1.ip_server
        port_tl1 = tl1.port_tl1

        datas = []
        pesan_param = 'Status ONU not found'
        ip_gpon = request.POST['ip_gpon'].splitlines()

        target = f'IP NMS: {ip_server}'
        logApp = logAppIn(request, page_title, target)

        if vendor_code == "fh" or vendor_code == "zte":
            # connect tl1 via socket
            s = socket(AF_INET, SOCK_STREAM)
            s.connect((ip_server, port_tl1))

            if vendor_code == "fh":
                # login tl1 fiberhome
                cmd_login = f'LOGIN:::CTAG::UN={tl1.user_tl1},PWD={tl1.pass_tl1};'
                s.send(cmd_login.encode())
                time.sleep(2)

                for ips in ip_gpon:
                    ip = ips.split(';')
                    cmd = f'LST-ONUSTATE::OLTID={ip[0]}:CTAG::;'
                    data_slot_port = ''
                    time_sleep = 7

                    if len(ip) > 1:
                        cmd = f'LST-ONUSTATE::OLTID={ip[0]},PONID=1-1-{ip[1]}:CTAG::;'
                        slot_port = ip[1].split('-')
                        slot = slot_port[0]
                        port = slot_port[1]
                        data_slot_port = f', SLOT/PORT: {slot}/{port}'
                        time_sleep = 2

                    if len(ip) > 2:
                        cmd = f'LST-ONUSTATE::OLTID={ip[0]},PONID=1-1-{ip[1]},ONUIDTYPE=MAC,ONUID={ip[2]}:CTAG::;'
                        slot_port = ip[1].split('-')
                        slot = slot_port[0]
                        port = slot_port[1]
                        data_slot_port = f', SLOT/PORT: {slot}/{port}, SN: {ip[2]}'
                        time_sleep = 2

                    log = LogTL1(target=f"IP GPON: {ip[0]}{data_slot_port}", action=f"{page_title} FIBERHOME", command=ips, time=datetime.now(), status='In Progress', message='No Error', logapp=logApp)
                    log.save()

                    tl1_cmd = tl1_command(s, cmd, datas, log, log.id, False, pesan_param, time_sleep)
                    if tl1_cmd['status'] == False:
                        logAppFailed(logApp.id)

                        return JsonResponse(
                            {
                                'status': tl1_cmd['status'],
                                'data': tl1_cmd['data']
                            }
                        )

                s.send(b'LOGOUT:::CTAG::;')

            else:
                for ips in ip_gpon:
                    ip = ips.split(';')

                    cmd = f'LST-ONUSTATE::OLTID={ip[0]}:CTAG::;'
                    data_slot_port = ''
                    time_sleep = 3

                    if len(ip) > 1:
                        cmd = f'LST-ONUSTATE::OLTID={ip[0]},PONID=1-1-{ip[1]}:CTAG::;'
                        slot_port = ip[1].split('-')
                        slot = slot_port[0]
                        port = slot_port[1]
                        data_slot_port = f', SLOT/PORT: {slot}/{port}'
                        time_sleep = 2

                    if len(ip) > 2:
                        cmd = f'LST-ONUSTATE::OLTID={ip[0]},PONID=1-1-{ip[1]},ONUIDTYPE=SN,ONUID={ip[2]}:CTAG::;'
                        slot_port = ip[1].split('-')
                        slot = slot_port[0]
                        port = slot_port[1]
                        data_slot_port = f', SLOT/PORT: {slot}/{port}, SN: {ip[2]}'
                        time_sleep = 3

                    log = LogTL1(target=f"IP GPON: {ip[0]}{data_slot_port}", action=f"{page_title} ZTE", time=datetime.now(), command=ips, logapp=logApp)
                    log.save()

                    tl1_cmd = tl1_command(s, cmd, datas, log, log.id, False, pesan_param, time_sleep)
                    if tl1_cmd['status'] == False:
                        logAppFailed(logApp.id)

                        return JsonResponse(
                            {
                                'status': tl1_cmd['status'],
                                'data': tl1_cmd['data']
                            }
                        )

            s.close()

            logAppSuccess(logApp.id)

            datas = '\n'.join(datas)
            request.session['hasil'] = datas
            request.session['hw'] = False
            return JsonResponse(
                {
                    'status': True,
                }
            )

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
def cekservice(request, vendor_code):
    if session_login(request) == 'zero':
        return redirect('login:formOtp')

    page_title = 'Cek Service'
    if request.is_ajax():
        tl1 = ServerTl1.objects.get(ip_server=request.POST['tl1_server'])
        ip_server = tl1.ip_server
        port_tl1 = tl1.port_tl1

        datas = []
        pesan_param = 'Service  ONU does not exist'
        ip_gpon = request.POST['ip_gpon'].splitlines()

        target = f'IP NMS: {ip_server}'
        logApp = logAppIn(request, page_title, target)

        if vendor_code == "fh" or vendor_code == "zte":
            # connect tl1 via socket
            s = socket(AF_INET, SOCK_STREAM)
            s.connect((ip_server, port_tl1))

            if vendor_code == "fh":
                # login tl1 fiberhome
                cmd_login = f'LOGIN:::CTAG::UN={tl1.user_tl1},PWD={tl1.pass_tl1};'
                s.send(cmd_login.encode())
                time.sleep(2)

                for ips in ip_gpon:
                    ip = ips.split(';')

                    slot_port = ip[1].split('-')
                    slot = slot_port[0]
                    port = slot_port[1]

                    datas.append(f"IP GPON: {ip[0]}, SLOT/PORT: {slot}/{port}, SN: {ip[2]}")
                    log = LogTL1(target=f"IP GPON: {ip[0]}, SLOT/PORT: {slot}/{port}, SN: {ip[2]}", action=f"{page_title} FIBERHOME", time=datetime.now(), command=ips, status='In Progress', message='No Error', logapp=logApp)
                    log.save()

                    datas.append('Register ONT')
                    cmd = f'LST-ONU::OLTID={ip[0]},PONID=1-1-{ip[1]},ONUIDTYPE=MAC,ONUID={ip[2]}:CTAG::;'
                    tl1_cmd = tl1_command(s, cmd, datas, log, log.id, False, pesan_param, 2)
                    if tl1_cmd['status'] == False:
                        logAppFailed(logApp.id)

                        return JsonResponse(
                            {
                                'status': tl1_cmd['status'],
                                'data': tl1_cmd['data']
                            }
                        )

                    datas.append('Status ONT')
                    cmd = f'LST-ONUSTATE::OLTID={ip[0]},PONID=1-1-{ip[1]},ONUIDTYPE=MAC,ONUID={ip[2]}:CTAG::;'
                    tl1_cmd = tl1_command(s, cmd, datas, log, log.id, False, pesan_param, 2)
                    if tl1_cmd['status'] == False:
                        logAppFailed(logApp.id)

                        return JsonResponse(
                            {
                                'status': tl1_cmd['status'],
                                'data': tl1_cmd['data']
                            }
                        )

                    datas.append('Service Internet')
                    cmd = f'LST-ONUWANSERVICECFG::OLTID={ip[0]},PONID=1-1-{ip[1]},ONUIDTYPE=MAC,ONUID={ip[2]}:CTAG::;'
                    tl1_cmd = tl1_command(s, cmd, datas, log, log.id, False, pesan_param, 2)
                    if tl1_cmd['status'] == False:
                        logAppFailed(logApp.id)

                        return JsonResponse(
                            {
                                'status': tl1_cmd['status'],
                                'data': tl1_cmd['data']
                            }
                        )

                    datas.append('Service Voice')
                    cmd = f'LST-POTS::OLTID={ip[0]},PONID=1-1-{ip[1]},ONUIDTYPE=MAC,ONUID={ip[2]}:CTAG::;'
                    tl1_cmd = tl1_command(s, cmd, datas, log, log.id, False, pesan_param, 2)
                    if tl1_cmd['status'] == False:
                        logAppFailed(logApp.id)
                         
                        return JsonResponse(
                            {
                                'status': tl1_cmd['status'],
                                'data': tl1_cmd['data']
                            }
                        )
                    cmd = f'LST-POTSINFO::OLTID={ip[0]},PONID=1-1-{ip[1]},ONUIDTYPE=MAC,ONUID={ip[2]}:CTAG::;'
                    tl1_cmd = tl1_command(s, cmd, datas, log, log.id, False, pesan_param, 2)
                    if tl1_cmd['status'] == False:
                        logAppFailed(logApp.id)
                         
                        return JsonResponse(
                            {
                                'status': tl1_cmd['status'],
                                'data': tl1_cmd['data']
                            }
                        )

                    datas.append('Service IPTV / WIFI / ASTINET / VPN')
                    cmd = f'LST-PORTVLAN::OLTID={ip[0]},PONID=1-1-{ip[1]},ONUIDTYPE=MAC,ONUID={ip[2]}:CTAG::;'
                    tl1_cmd = tl1_command(s, cmd, datas, log, log.id, False, pesan_param, 2)
                    if tl1_cmd['status'] == False:
                        logAppFailed(logApp.id)
                         
                        return JsonResponse(
                            {
                                'status': tl1_cmd['status'],
                                'data': tl1_cmd['data']
                            }
                        )

                s.send(b'LOGOUT:::CTAG::;')

            else:
                for ips in ip_gpon:
                    ip = ips.split(';')

                    slot_port = ip[1].split('-')
                    slot = slot_port[0]
                    port = slot_port[1]

                    datas.append(f'IP GPON : {ip[0]}, SLOT/PORT : {slot}/{port}, SN ; {ip[2]}')
                    log = LogTL1(target=f"IP GPON: {ip[0]}, SLOT/PORT: {slot}/{port}, SN: {ip[2]}", action=f"{page_title} ZTE", time=datetime.now(), command=ips, status='In Progress', message='No Error', logapp=logApp)
                    log.save()

                    datas.append('Register ONT')
                    cmd = f'LST-ONU::OLTID={ip[0]},PONID=1-1-{ip[1]},ONUIDTYPE=SN,ONUID={ip[2]}:CTAG::;'
                    tl1_cmd = tl1_command(s, cmd, datas, log, log.id, False, pesan_param, 2)
                    if tl1_cmd['status'] == False:
                        logAppFailed(logApp.id)
                         
                        return JsonResponse(
                            {
                                'status': tl1_cmd['status'],
                                'data': tl1_cmd['data']
                            }
                        )

                    datas.append('Status ONT')
                    cmd = f'LST-ONUSTATE::OLTID={ip[0]},PONID=1-1-{ip[1]},ONUIDTYPE=SN,ONUID={ip[2]}:CTAG::;'
                    tl1_cmd = tl1_command(s, cmd, datas, log, log.id, False, pesan_param, 2)
                    if tl1_cmd['status'] == False:
                        logAppFailed(logApp.id)
                         
                        return JsonResponse(
                            {
                                'status': tl1_cmd['status'],
                                'data': tl1_cmd['data']
                            }
                        )

                    datas.append('Service PORT')
                    cmd = f'LST-SERVICEPORT::DID={ip[0]},OID={ip[2]}:CTAG::;'
                    tl1_cmd = tl1_command(s, cmd, datas, log, log.id, False, pesan_param, 2)
                    if tl1_cmd['status'] == False:
                        logAppFailed(logApp.id)
                         
                        return JsonResponse(
                            {
                                'status': tl1_cmd['status'],
                                'data': tl1_cmd['data']
                            }
                        )

                    datas.append('Service Internet')
                    cmd = f'LST-ONUWANIP::DID={ip[0]},OID={ip[2]}:CTAG::;'
                    tl1_cmd = tl1_command(s, cmd, datas, log, log.id, False, pesan_param, 2)
                    if tl1_cmd['status'] == False:
                        logAppFailed(logApp.id)
                         
                        return JsonResponse(
                            {
                                'status': tl1_cmd['status'],
                                'data': tl1_cmd['data']
                            }
                        )

                    datas.append('Service Voice')
                    cmd = f'LST-POTSINFO::OLTID={ip[0]},PONID=1-1-{ip[1]},ONUIDTYPE=MAC,ONUID={ip[2]},ONUPORT=1-1-1-1:CTAG::;'
                    tl1_cmd = tl1_command(s, cmd, datas, log, log.id, False, pesan_param, 2)
                    if tl1_cmd['status'] == False:
                        logAppFailed(logApp.id)

                        return JsonResponse(
                            {
                                'status': tl1_cmd['status'],
                                'data': tl1_cmd['data']
                            }
                        )

                    datas.append('Service Port Vlan')
                    cmd = f'LST-PORTVLAN::OLTID={ip[0]},PONID=1-1-{ip[1]},ONUIDTYPE=MAC,ONUID={ip[2]}:CTAG::;'
                    tl1_cmd = tl1_command(s, cmd, datas, log, log.id, False, pesan_param, 2)
                    if tl1_cmd['status'] == False:
                        logAppFailed(logApp.id)
                            
                        return JsonResponse(
                            {
                                'status': tl1_cmd['status'],
                                'data': tl1_cmd['data']
                            }
                        )

            s.close()
            request.session['hw'] = False
        else:
            user_name = tl1.user_tl1
            passwd = tl1.pass_tl1
            ip_server = tl1.ip_server

            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(hostname=ip_server, username=user_name, password=passwd)

            for ips_gpon in ip_gpon:
                ip = ips_gpon.split(';')
                sp = ip[1].split('-')
                slot = sp[0]
                port = sp[1]
                onu_id = ip[2]
                datas.append(f'HOST: {ip[0]}, SLOT/PORT: {slot}/{port}, ONU ID: {onu_id}')
                command = f"telnet {ip[0]}"
                cmd_gpon = f"""{tl1.user_tl1}
{tl1.pass_tl1}
enable
scroll

config

display service-port port 0/{slot}/{port} ont {onu_id}

display ont wan-info 0/{slot} {port} {onu_id}

interface gpon 0/{slot}

display ont port state {port} {onu_id} pots-port all

quit

quit

quit
y

"""
                stdin, stdout, stderr = ssh_client.exec_command(command)
                time.sleep(1)

                log = LogTL1(target=f'IP GPON: {ip[0]}, SLOT/PORT: {slot}/{port}, ONU ID: {onu_id}', action=f"{page_title} HUAWEI", command=ip, time=datetime.now(), status='In Progress', message='No Error', logapp=logApp)
                log.save()

                stdin.write(cmd_gpon)
                hasil = stdout.read().decode()

                if 'The required ONT does not exist' in hasil:
                    status = 'Failed'
                    pesan = 'No Unregister ONU'
                elif 'Incomplete command, the error locates at' in hasil:
                    status = 'Failed'
                    pesan = 'Format is wrong'
                else:
                    status = "Success"
                    pesan = 'No Error'

                cmd_tl1 = CmdTL1(command_tl1='display ont autofind all', logtl1=log, result_tl1=hasil)
                cmd_tl1.save()

                datas.append(hasil)

                log = LogTL1.objects.get(pk=log.id)
                log.stoptime = datetime.now()
                log.status = status
                log.message = pesan
                log.save()

                ssh_client.exec_command("logout")
                ssh_client.close()
                request.session['hw'] = True

        logAppSuccess(logApp.id)
        datas = '\n'.join(datas)
        request.session['hasil'] = datas
        return JsonResponse(
            {
                'status': True,
            }
        )

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
@user_passes_test(check_permissions)
def wifiService(request, vendor_code):
    if session_login(request) == 'zero':
        return redirect('login:formOtp')

    page_title = 'Wifi Service'
    vendor = ServerTl1.objects.values('vendor').order_by('vendor').annotate(vcount=Count('vendor'))
    if request.is_ajax():
        s = socket(AF_INET, SOCK_STREAM)

        tl1 = ServerTl1.objects.get(vendor=vendor_code, server_gpon__ip_gpon=request.POST['ip_gpon'])
        ip_server = tl1.ip_server
        port_tl1 = tl1.port_tl1
        s.connect((ip_server, port_tl1))
        datas = []

        cmd_login = f'LOGIN:::CTAG::UN={tl1.user_tl1},PWD={tl1.pass_tl1};'
        s.send(cmd_login.encode())
        time.sleep(2)
        s.recv(80000).decode()

        ip_gpon = request.POST['ip_gpon']
        slot = request.POST['slot']
        port = request.POST['port']
        sn = request.POST['sn']
        status_code = False

        target = f'IP NMS: {ip_server}, IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}'
        logApp = logAppIn(request, page_title, target)

        if 'cek_WIFI' in request.POST:
            log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"{page_title} FIBERHOME", time=datetime.now(), command='No Command', status='In Progress', message='No Error', logapp=logApp)
            log.save()

            cmd = f'LST-WIFISERVICE::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn}:CTAG::;'
            s.send(cmd.encode())
            time.sleep(2)
            data_recv = s.recv(80000).decode()
            begin_word = data_recv.find('ENDESC=No error ;') + 1
            cmd_tl1 = CmdTL1(command_tl1=cmd, logtl1=log, result_tl1=data_recv[begin_word:])
            cmd_tl1.save()

            if 'block_records=1' in data_recv:
                status = "Success"
                pesan = 'No Error'
                status_code = True
                begin_word = data_recv.find('List of Onu')
                datas.append(data_recv[begin_word:])

            elif 'EADD=object not exist, please check' in data_recv:
                status = 'Failed'
                status_code = False
                pesan = 'ONU does not exist'
                datas = pesan
                logAppFailed(logApp.id)

            elif 'ENDESC=invalid parameter format' in data_recv:
                status = 'Failed'
                status_code = False
                pesan = 'IP GPON does not exist'
                datas = pesan
                logAppFailed(logApp.id)

            else:
                status = 'Failed'
                status_code = False
                pesan = 'There is error'
                datas = pesan

            log = LogTL1.objects.get(pk=log.id)
            log.stoptime = datetime.now()
            log.status = status
            log.message = pesan
            log.save()

        if 'ubah_WIFI' in request.POST:
            SSID = request.POST['SSID']
            nama_SSID = request.POST['nama_SSID']
            ssid_AUTH = request.POST['ssid_AUTH']
            ssid_Encryptype = request.POST['ssid_Encryptype']
            wifi_ENABLE = request.POST['wifi_ENABLE']
            ssid_ENABLE = request.POST['ssid_ENABLE']
            hidden_ENABLE = request.POST['hidden_ENABLE']
            pass_SSID = request.POST['pass_SSID']
            config_SSID = request.POST['config_SSID']


            log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"{page_title} FIBERHOME", time=datetime.now(), command='No Command', status='In Progress', message='No Error', logapp=logApp)
            log.save()

            if config_SSID == 'Modify':
                cmd = f'MODIFY-WIFISERVICE::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn}:CTAG::ENABLE={wifi_ENABLE},WILESS-STANDARD=802.11bgn,WORKING-FREQUENCY=2.4GHZ,FREQUENCY-BANDWIDTH=20/40MHZ,WILESS-AREA=0,WILESS-CHANNEL=0,T-POWER=100,SSID={SSID},SSID-ENABLE={ssid_ENABLE},SSID-NAME={nama_SSID},SSID-VISIBALE={hidden_ENABLE},AUTH-MODE={ssid_AUTH},ENCRYP-TYPE={ssid_Encryptype},PRESHARED-KEY={pass_SSID},UPDATEKEY-INTERVAL=0;'
            else:
                cmd = f'CFG-WIFISERVICE::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn}:CTAG::ENABLE={wifi_ENABLE},WILESS-STANDARD=802.11bgn,WORKING-FREQUENCY=2.4GHZ,FREQUENCY-BANDWIDTH=20/40MHZ,WILESS-AREA=0,WILESS-CHANNEL=0,T-POWER=100,SSID={SSID},SSID-ENABLE={ssid_ENABLE},SSID-NAME={nama_SSID},SSID-VISIBALE={hidden_ENABLE},AUTH-MODE={ssid_AUTH},ENCRYP-TYPE={ssid_Encryptype},PRESHARED-KEY={pass_SSID};'

            s.send(cmd.encode())
            time.sleep(2)
            data_recv = s.recv(80000).decode()
            begin_word = data_recv.find('ENDESC=No error ;') + 1
            cmd_tl1 = CmdTL1(command_tl1=cmd, logtl1=log, result_tl1=data_recv[begin_word:])
            cmd_tl1.save()

            if 'ENDESC=No error' in data_recv:
                status = "Success"
                status_code = True
                pesan = 'Success Configure Wifi'
                datas = pesan
            elif 'EADD=object not exist, please check' in data_recv:
                status = 'Failed'
                status_code = False
                pesan = 'ONU does not exist'
                datas = pesan
                logAppFailed(logApp.id)

            elif 'ENDESC=invalid parameter format' in data_recv:
                status = 'Failed'
                status_code = False
                pesan = 'IP GPON does not exist'
                datas = pesan
                logAppFailed(logApp.id)

            else:
                status = 'Failed'
                status_code = False
                pesan = 'There is error'
                datas = pesan
                logAppFailed(logApp.id)

            log = LogTL1.objects.get(pk=log.id)
            log.stoptime = datetime.now()
            log.status = status
            log.message = pesan
            log.save()

        s.close()

        logAppSuccess(logApp.id)

        return JsonResponse(
            {
                'status': status_code,
                'data' : datas
            }
        )

    else:
        sto = Sto.objects.order_by('sto_code').annotate(scount=Count('sto_code')).filter(sto_gpon__ip_server__vendor=vendor_code)
        vendor_name = vendor_code
        context = {
            'page_title': page_title,
            'vendors': vendor,
            'vendor_name': vendor_name,
            'stos' : sto,
            'client_ip': get_client_ip(request),
        }

        return render(request, 'wifiservice.html', context)

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
@user_passes_test(check_permissions)
def cekSto(request):
    if request.is_ajax():
        gpon = GponDevice.objects.filter(sto__sto_code=request.POST['sto'], ip_server__vendor=request.POST['vendor'])
        if gpon.count() > 0:
            status = True
            gpon_serial = GponSerializer(gpon, many=True)
        else:
            status = False
            gpon_serial = None

        data = {
            'status_code': status,
            'data': gpon_serial.data
        }
        return JsonResponse(data, safe=False)

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
def sop(request, sop_tipe):
    if session_login(request) == 'zero':
        return redirect('login:formOtp')

    if sop_tipe == "configbatch":
        placeholder = "Contoh Fiberhome :\n"
        placeholder += "=====CREATE ONT==========\n"
        placeholder += "ont|fh|172.29.215.6|6-6|FHTT06138248\n"
        placeholder += "ont|fh|172.29.215.6|6-6|FHTT06138248|HG6243C\n"
        placeholder += "ont|fh|172.29.215.6|6-6|FHTT06138248|HG6243C|{NAMA_PELANGGAN}\n"
        placeholder += "=====CREATE INTERNET==========\n"
        placeholder += "other|fh|172.29.215.6|6-6|FHTT06138248;INET|1904|131626153157@telkom.net|707341163\n"
        placeholder += "other|fh|172.29.215.6|6-6|FHTT06138248;INET|1904|131626153157@telkom.net|707341163|1536K|15360K\n"
        placeholder += "=====CREATE VOICE==========\n"
        placeholder += "other|fh|172.29.215.6|6-6|FHTT06138248;VOICE|532|+622666221191|190718488\n"
        placeholder += "=====CREATE IPTV==========\n"
        placeholder += "other|fh|172.29.215.6|6-6|FHTT06138248;IPTV\n"
        placeholder += "=====CREATE 3P/2P/1P + ONT==========\n"
        placeholder += "ont|fh|172.29.215.6|6-6|FHTT06138248|HG6243C|NAMA_PELANGGAN;INET|1904|131626153157@telkom.net|707341163|1536K|15360K;VOICE|532|+622666221191|190718488;IPTV\n"
        placeholder += "\n"
        placeholder += "\n"
        placeholder += "Contoh ZTE :\n"
        placeholder += "=====CREATE ONT==========\n"
        placeholder += "ont|zte|172.21.202.4|12-2|ZTEGC6753017\n"
        placeholder += "ont|zte|172.21.202.4|12-2|ZTEGC6753017|ZTEG-F609\n"
        placeholder += "ont|zte|172.21.202.4|12-2|ZTEGC6753017|ZTEG-F609|NAMA_PELANGGAN\n"
        placeholder += "=====CREATE INTERNET==========\n"
        placeholder += "other|zte|172.21.202.4|12-2|ZTEGC6753017;INET|770|131626153157@telkom.net|707341163|\n"
        placeholder += "other|zte|172.21.202.4|12-2|ZTEGC6753017;INET|770|131626153157@telkom.net|707341163|{vport}\n"
        placeholder += "other|zte|172.21.202.4|12-2|ZTEGC6753017;INET|770|131626153157@telkom.net|707341163|{vport}|1536K|15360K\n"
        placeholder += "=====CREATE VOICE==========\n"
        placeholder += "other|zte|172.21.202.4|12-2|ZTEGC6753017;VOICE|571|+622667121278|9866556\n"
        placeholder += "other|zte|172.21.202.4|12-2|ZTEGC6753017;VOICE|571|+622667121278|9866556|{vport}\n"
        placeholder += "=====CREATE IPTV==========\n"
        placeholder += "other|zte|172.21.202.4|12-2|ZTEGC6753017;IPTV\n"
        placeholder += "=====CREATE 3P/2P/1P + ONT==========\n"
        placeholder += "ont|zte|172.21.202.4|12-2|ZTEGC6753017|ZTEG-F609|NAMA_PELANGGAN;INET|770|131626153157@telkom.net|707341163|1|1536K|15360K;VOICE|571|+622667121278|9866556|2;IPTV\n"
    else:
        placeholder = "Contoh Fiberhome :\n"
        placeholder += "=====DELETE ONT==========\n"
        placeholder += "ont|fh|172.29.215.6|6-6|FHTT06138248\n"
        placeholder += "=====DELETE INTERNET==========\n"
        placeholder += "other|fh|172.29.215.6|6-6|FHTT06138248;INET|1904\n"
        placeholder += "=====DELETE VOICE==========\n"
        placeholder += "other|fh|172.29.215.6|6-6|FHTT06138248;VOICE\n"
        placeholder += "=====DELETE IPTV==========\n"
        placeholder += "other|fh|172.29.215.6|6-6|FHTT06138248;IPTV\n"
        placeholder += "\n"
        placeholder += "\n"
        placeholder += "Contoh ZTE :\n"
        placeholder += "=====DELETE ONT==========\n"
        placeholder += "ont|zte|172.21.202.4|12-2|ZTEGC6753017\n"
        placeholder += "=====CREATE INTERNET==========\n"
        placeholder += "other|zte|172.21.202.4|12-2|ZTEGC6753017;INET|770\n"
        placeholder += "=====CREATE VOICE==========\n"
        placeholder += "other|zte|172.21.202.4|12-2|ZTEGC6753017;VOICE|571\n"
        placeholder += "=====CREATE IPTV==========\n"
        placeholder += "other|zte|172.21.202.4|12-2|ZTEGC6753017;IPTV\n"

    datas = placeholder.splitlines()
    vendor = ServerTl1.objects.values('vendor').order_by('vendor').annotate(vcount=Count('vendor'))

    context = {
        'page_title' : 'SOP',
        'datas' : datas,
        'vendors' : vendor,
        'client_ip': get_client_ip(request),
    }

    return render(request, 'sop.html', context)

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
@user_passes_test(check_permissions)
def config_gui(request, vendor_code):
    if session_login(request) == 'zero':
        return redirect('login:formOtp')

    page_title = "CEK ONT"

    if request.method == 'POST':
        if request.is_ajax():
            s = socket(AF_INET, SOCK_STREAM)
            tl1 = ServerTl1.objects.get(vendor=vendor_code, server_gpon__ip_gpon=request.POST['ip_gpon'])

            ip_server = tl1.ip_server
            port_tl1 = tl1.port_tl1
            s.connect((ip_server, port_tl1))
            cmd_login = f'LOGIN:::CTAG::UN={tl1.user_tl1},PWD={tl1.pass_tl1};'
            s.send(cmd_login.encode())
            time.sleep(2)
            s.recv(80000).decode()

            ip_gpon = request.POST['ip_gpon']
            slot = request.POST['slot']
            port = request.POST['port']
            sn = request.POST['sn']

            target = f'IP NMS: {ip_server}, IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}'
            logApp = logAppIn(request, page_title, target)

            log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Cek SN FIBERHOME", time=datetime.now(), command='No Command', username=request.user, status='In Progress', message='No Error', logapp=logApp)
            log.save()

            cmd = f'LST-ONU::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn}:CTAG::;'
            s.send(cmd.encode())
            time.sleep(2)
            data_recv = s.recv(80000).decode()
            cmd_tl1 = CmdTL1(command_tl1=cmd, logtl1=log, result_tl1=data_recv)
            cmd_tl1.save()

            if 'block_records=1' in data_recv or 'totalrecord=1' in data_recv:
                status = "Success"
                pesan = 'ONU already exist'
                status_code = True
                datas = pesan
                logAppFailed(logApp.id)
            elif 'EADD=object not exist, please check' in data_recv or 'ENDESC=device does not exist (the onu does not exist)' in data_recv:
                status = 'Failed'
                status_code = False
                pesan = 'ONU does not exist'
                datas = pesan
                logAppFailed(logApp.id)
            elif 'ENDESC=invalid parameter format' in data_recv:
                status = 'Failed'
                status_code = False
                pesan = 'IP GPON does not exist'
                datas = pesan
                logAppFailed(logApp.id)
            else:
                status = 'Failed'
                status_code = False
                pesan = 'There is error'
                datas = pesan
                logAppFailed(logApp.id)

            log = LogTL1.objects.get(pk=log.id)
            log.stoptime = datetime.now()
            log.status = status
            log.message = pesan
            log.save()

            s.close()

            logAppSuccess(logApp.id)

            return JsonResponse(
                {
                    'status': status_code,
                    'data': datas
                }
            )
    else:
        vendor = ServerTl1.objects.values('vendor').order_by('vendor').annotate(vcount=Count('vendor'))
        sto = Sto.objects.order_by('sto_code').annotate(scount=Count('sto_code')).filter(sto_gpon__ip_server__vendor=vendor_code)

        if vendor_code == 'zte':
            tipe_ont = {
                'ZTEG-F660' : 'ZXHN_F660',
                'ZTEG-F609' : 'ZXHN_F609',
                'ZTEG-F670': 'ZXHN_F670',
            }

        else:
            tipe_ont = {
                'AN5506-04-F1' : 'AN5506-04-F1',
                'HG6243C' : 'HG6243C',
            }

        context = {
            'page_title': 'CONFIG GUI',
            'vendor_name' : vendor_code,
            'vendors': vendor,
            'stos' : sto,
            'tipe_ont' : tipe_ont,
            'client_ip': get_client_ip(request),
        }

        return render(request, 'config_vendor.html', context)

def logAppIn(request, action, target):
    logApp = LogApp(status='In Progress', time=datetime.now(), ip_client=get_client_ip(request), username=request.user, action=action, target=target)
    logApp.save();

    return logApp

def logAppFailed(logAppId):
    logAppFailed = LogApp.objects.get(pk=logAppId)
    logAppFailed.status = "Failed"
    logAppFailed.stoptime = datetime.now()
    logAppFailed.save()

def logAppSuccess(logAppId):
    logAppSuccess = LogApp.objects.get(pk=logAppId)
    logAppSuccess.status = "Success"
    logAppSuccess.stoptime = datetime.now()
    logAppSuccess.save()

def save_log(log_id, status, pesan):
    log = LogTL1.objects.get(pk=log_id)
    log.stoptime = datetime.now()
    log.status = status
    log.message = pesan
    log.save()

def list_error_cek(log_id, data_recv, param_pesan):
    if 'block_records=0' in data_recv or 'totalrecord=0' in data_recv or 'ENDESC=device does not exist (the onu does not exist)' in data_recv:
        status = 'Failed'
        status_array = True
        pesan = param_pesan
    else:
        status_array = False

        if 'EADD=object not exist, please check' in data_recv:
            status = 'Failed'
            pesan = 'ONU does not exist'

        elif 'ENDESC=resource does not exist (NE topo node)' in data_recv:
            status = 'Failed'
            pesan = 'IP GPON does not exist'

        elif 'ENDESC=invalid parameter format' in data_recv or 'INVALID SYNTAX OR PUNCTUATION' in data_recv or 'ILLEGAL COMMAND CODE' in data_recv or 'ENDESC=exception happensjava.lang.NullPointerException' in data_recv:
            status = 'Failed'
            pesan = 'There is something went wrong'

        else:
            status = 'Success'
            status_array = True
            pesan = 'No Error'

    save_log(log_id, status, pesan)

    return {
        'status': status_array,
        'data': pesan
    }

def list_error(log_id, data_recv):
    status = 'Failed'
    status_array = False

    if 'ENDESC=No error' in data_recv or 'ENDESC=No Error' in data_recv:
        status = "Success"
        status_array = True
        pesan = 'No Error'

    elif 'EADD=object not exist, please check' in data_recv or 'ENDESC=resource does not exist (ONU)' in data_recv:
        pesan = 'ONU does not exist'

    elif 'ENDESC=invalid parameter format' in data_recv or 'ENDESC=device does not exist' in data_recv:
        pesan = 'IP GPON does not exist'

    elif 'INVALID SYNTAX OR PUNCTUATION' in data_recv or 'ILLEGAL COMMAND CODE' in data_recv or 'ENDESC=exception happensjava.lang.NullPointerException' in data_recv:
        pesan = 'Format is Wrong'

    elif 'EADD=onu already exist' in data_recv or 'ENDESC=device operation failed (GPON ONU sn already exists.)' in data_recv:
        pesan = 'ONU already exist'

    elif 'EADD=service not exist' in data_recv:
        pesan = 'Service not exist'

    elif 'ENDESC=resource conflicts (NAME)' in data_recv:
        pesan = 'ONU name already exist'

    elif 'EADD=server check input parameter error' in data_recv:
        pesan = 'Bandwith profile does not exist'

    elif 'EADD=service already exist' in data_recv:
        pesan = 'Service already exist'

    elif 'ENDESC=device operation failed (T-CONT name already exists.)' in data_recv:
        pesan = 'Service Port already exist'

    elif 'ENDESC=resource does not exist (traffic profile)' in data_recv:
        pesan = 'Upload profile does not exist'

    elif 'ENDESC=resource does not exist (bandwidth profile)' in data_recv:
        pesan = 'Download profile does not exist'

    elif 'EADD=NGN User Data UserIndex Repeat' in data_recv:
        pesan = 'Voice already exist'

    elif 'EADD=ngnvlan is not defined, please check' in data_recv:
        pesan = 'Vlan voice does not exist'

    elif 'EADD=Can`t config the same VID when the connect type is the same' in data_recv or 'EADD=only one INTERNET mode wanservice could be set on one port' in data_recv:
        pesan = 'Wan COS must be set same with NMS'

    else:
        pesan = 'There is something wrong'

    save_log(log_id, status, pesan)

    return {
        'status': status_array,
        'data': pesan
    }

def tl1_command(sockets, cmd, datas, log, log_id, cek = True, param_pesan='', time_sleep=2):
    save_log(log_id, 'Progress', 'No Error')

    sockets.send(cmd.encode())
    time.sleep(time_sleep)
    data_recv = sockets.recv(128000000).decode()
    cmd_tl1 = CmdTL1(command_tl1=cmd, logtl1=log, result_tl1=data_recv)
    cmd_tl1.save()
    datas.append(cmd)
    datas.append(data_recv)

    if cek == True:
        ls_err = list_error(log_id, data_recv)
    else:
        ls_err = list_error_cek(log_id, data_recv, param_pesan)

    return ls_err

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
@user_passes_test(check_permissions)
def config(request, vendor_code):
    if request.is_ajax():
        if session_login(request) == 'zero':
            return redirect('login:formOtp')

        if 'ip_gpon' not in request.POST:
            return JsonResponse(
                {
                    'status' : False,
                    'data' : 'IP GPON does not exist!!!'
                }
            )

        page_title = "CONFIG GUI"

        tl1 = ServerTl1.objects.get(vendor=vendor_code, server_gpon__ip_gpon=request.POST['ip_gpon'])
        ip_server = tl1.ip_server
        port_tl1 = tl1.port_tl1
        s = socket(AF_INET, SOCK_STREAM)
        datas = []

        ip_gpon = request.POST['ip_gpon']
        slot = request.POST['slot']
        port = request.POST['port']
        tipe_ont = request.POST['tipe_ont']
        sn = request.POST['sn']
        nama_pel = request.POST['nama_pel']
        create_ont = request.POST['create_ont']
        action = request.POST['action']
        services = request.POST.getlist('service_name')

        target = f'IP NMS: {ip_server}, IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}'
        logApp = logAppIn(request, page_title, target)

        if vendor_code == 'fh':
            vendor_name = "FIBERHOME"
            s.connect((ip_server, port_tl1))
            cmd_login = f'LOGIN:::CTAG::UN={tl1.user_tl1},PWD={tl1.pass_tl1};'
            s.send(cmd_login.encode())
            time.sleep(2)
            data = s.recv(80000)
            datas.append(data.decode())

            if nama_pel == "":
                cmd_create_ont = f'ADD-ONU::OLTID={ip_gpon},PONID=1-1-{slot}-{port}:5::AUTHTYPE=MAC,ONUID={sn},ONUTYPE={tipe_ont};'

            else:
                cmd_create_ont = f'ADD-ONU::OLTID={ip_gpon},PONID=1-1-{slot}-{port}:5::AUTHTYPE=MAC,ONUID={sn},ONUTYPE={tipe_ont},NAME={nama_pel} | {sn};'

            cmd_delete_ont = f'DEL-ONU::OLTID={ip_gpon},PONID=1-1-{slot}-{port}:5::ONUIDTYPE=MAC,ONUID={sn};'

        else:
            vendor_name = "ZTE"
            s.connect((ip_server, port_tl1))

            if nama_pel == "":
                cmd_create_ont = f'ADD-ONU::OLTID={ip_gpon},PONID=1-1-{slot}-{port}:5::AUTHTYPE=SN,ONUID={sn},ONUTYPE={tipe_ont};'

            else:
                cmd_create_ont = f'ADD-ONU::OLTID={ip_gpon},PONID=1-1-{slot}-{port}:5::AUTHTYPE=SN,ONUID={sn},ONUTYPE={tipe_ont},NAME={nama_pel}|{sn};'

            cmd_delete_ont = f'DEL-ONU::OLTID={ip_gpon},PONID=1-1-{slot}-{port}:5::ONUIDTYPE=SN,ONUID={sn};'

        command = f'ont|{vendor_code}|{ip_gpon}|{slot}-{port}|{sn}|{tipe_ont}'

        if create_ont == "Create ONT" and action == "Config" :
            datas.append('###################CREATE ONT###################')

            log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Register ONT {vendor_name}", time=datetime.now(), command=command, status='In Progress', message='No Error', logapp=logApp)
            log.save()

            tl1_cmd = tl1_command(s, cmd_create_ont, datas, log, log.id)
            if tl1_cmd['status'] == False:
                logAppFailed(logApp.id)
                    
                return JsonResponse(
                    {
                        'status' : tl1_cmd['status'],
                        'data' : tl1_cmd['data']
                    }
                )


        elif create_ont == "Create ONT" and action == "Delete" :
            datas.append('###################DELETE ONT###################')

            log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Delete ONT {vendor_name}", time=datetime.now(), command=command, status='In Progress', message='No Error', logapp=logApp)
            log.save()

            tl1_cmd = tl1_command(s, cmd_delete_ont, datas, log, log.id)
            if tl1_cmd['status'] == False:
                logAppFailed(logApp.id)
                    
                return JsonResponse(
                    {
                        'status' : tl1_cmd['status'],
                        'data' : tl1_cmd['data']
                    }
                )

        if action == "Config" :
            for service in services:
                if service == "IPTV":
                    lan_IPTV = request.POST.getlist('lan_IPTV')
                    lan_CMD = ''
                    datas.append(f'###################Configure {service}###################')

                    for lan in lan_IPTV:
                        lan_CMD += f'-{lan}'

                    command = f'other|{vendor_code}|{ip_gpon}|{slot}-{port}|{sn};iptv|{lan_CMD[1:]}'
                    log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Configure IPTV {vendor_name}", time=datetime.now(), command=command, status='In Progress', message='No Error', logapp=logApp)
                    log.save()

                    if vendor_code == "fh":
                        for lan in lan_IPTV:
                            cmd = f'ADD-LANIPTVPORT::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn},ONUPORT=1-1-1-{lan}:5::MVLAN=110,MCOS=4;'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                    
                                return JsonResponse(
                                    {
                                        'status' : tl1_cmd['status'],
                                        'data' : tl1_cmd['data']
                                    }
                                )

                            cmd = f'CFG-LANPORTVLAN::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn},ONUPORT=1-1-1-{lan}:5::CVLAN=111,CCOS=4;'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                    
                                return JsonResponse(
                                    {
                                        'status' : tl1_cmd['status'],
                                        'data' : tl1_cmd['data']
                                    }
                                )

                            cmd = f'CFG-LANPORT::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn},ONUPORT=1-1-1-{lan}:5::BW=DOWN8MKA4_UP2253KA4;'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                                              
                                return JsonResponse(
                                    {
                                        'status' : tl1_cmd['status'],
                                        'data' : tl1_cmd['data']
                                    }
                                )

                    else:
                        cmd = f'ADD-PONVLAN::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn}:5::CVLAN=111,UV=111,SERVICENAME=USEETV;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                                                      
                            return JsonResponse(
                                {
                                    'status' : tl1_cmd['status'],
                                    'data' : tl1_cmd['data']
                                }
                            )

                        cmd = f'CFG-ONUBW::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn}:5::UPBW=UP-2253KA4,DOWNBW=DOWN-9012KA4,SERVICENAME=USEETV;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                                                      
                            return JsonResponse(
                                {
                                    'status' : tl1_cmd['status'],
                                    'data' : tl1_cmd['data']
                                }
                            )



                        for lan in lan_IPTV:
                            cmd = f'ADD-LANIPTVPORT::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn},ONUPORT=1-1-1-{lan}:5::MVLAN=110,SERVICENAME=USEETV;'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status' : tl1_cmd['status'],
                                        'data' : tl1_cmd['data']
                                    }
                                )

                            cmd = f'CFG-LANPORT::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn},ONUPORT=1-1-1-{lan}:5::VLANMOD=Hybrid,PVID=111;'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status' : tl1_cmd['status'],
                                        'data' : tl1_cmd['data']
                                    }
                                )

                            cmd = f'CHG-ONUUNI-PON::DID={ip_gpon},OID={sn},ONUPORT={lan}:5::IPRETRIEVEMODE=FromNetwork;'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status' : tl1_cmd['status'],
                                        'data' : tl1_cmd['data']
                                    }
                                )

                if service == "VOICE":
                    vlan_VOICE = request.POST['vlan_VOICE']
                    pots = request.POST['lan_VOICE']
                    vport_VOICE = request.POST['vport_VOICE'] if 'vport_VOICE' in request.POST else ''
                    bw_up_VOICE = request.POST['bw_up_VOICE']
                    bw_down_VOICE = request.POST['bw_down_VOICE']
                    user_VOICE_split = request.POST['user_accout_VOICE'].split('@')
                    user_VOICE = user_VOICE_split[0]
                    domain_VOICE = user_VOICE_split[1]
                    pass_VOICE = request.POST['pass_accout_VOICE']

                    datas.append(f'###################Configure {service}###################')

                    if vendor_code == "fh":
                        command = f'other|{vendor_code}|{ip_gpon}|{slot}-{port}|{sn};voice|{vlan_VOICE}|{user_VOICE}@{domain_VOICE}|{pass_VOICE}'
                        log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Configure {service} {vendor_name}", time=datetime.now(), command=command, status='In Progress', message='No Error', logapp=logApp)
                        log.save()

                        cmd = f'CFG-VOIPSERVICE::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn},ONUPORT=1-1-1-{pots}:5::PHONENUMBER={user_VOICE},PT=SIP,VOIPVLAN={vlan_VOICE},SCOS=7,EID=@{domain_VOICE},SIPUSERNAME={user_VOICE},SIPUSERPWD={pass_VOICE},IPMODE=DHCP;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                    else:
                        command = f'other|{vendor_code}|{ip_gpon}|{slot}-{port}|{sn};voice|{vlan_VOICE}|{user_VOICE}@{domain_VOICE}|{pass_VOICE}|{vport_VOICE}'
                        log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Configure {service} {vendor_name}", time=datetime.now(), command=command, status='In Progress', message='No Error', logapp=logApp)
                        log.save()

                        cmd = f'ADD-PONVLAN::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn}:5::CVLAN={vlan_VOICE},UV={vlan_VOICE},SERVICENAME=VOIP;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'CFG-ONUBW::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn}:5::UPBW=UP-{bw_up_VOICE},DOWNBW=DOWN-{bw_down_VOICE},SERVICENAME=VOIP;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status' : tl1_cmd['status'],
                                    'data' : tl1_cmd['data']
                                }
                            )

                        cmd = f'CHG-PORT-DHCP::DID={ip_gpon},OID={sn}:5::VIFID={vport_VOICE},OPTION82STAT=Enable;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status' : tl1_cmd['status'],
                                    'data' : tl1_cmd['data']
                                }
                            )

                        cmd = f'CFG-VOIPSERVICE::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn},ONUPORT=1-1-1-{pots}:5::PT=SIP,PHONENUMBER={user_VOICE},SIPREGDM="10.0.0.10::10.0.0.40",SIPUSERNAME={user_VOICE}@{domain_VOICE},SIPUSERPWD={pass_VOICE},VOIPVLAN={vlan_VOICE},CCOS=0,IPMODE=DHCP,IPHOSTID=2;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status' : tl1_cmd['status'],
                                    'data' : tl1_cmd['data']
                                }
                            )

                if service == "INET":
                    vlan_INET = request.POST['vlan_INET']
                    cos_INET = request.POST['cos_INET'] if 'cos_INET' in request.POST else ''
                    lan_INET = request.POST.getlist('lan_INET') if 'lan_INET' in request.POST else ''
                    lan_CMD = ''
                    ssid_INET = request.POST.getlist('ssid_INET') if 'ssid_INET' in request.POST else ''
                    user_INET_split = request.POST['user_accout_INET'].split('@')
                    user_INET = user_INET_split[0]
                    domain_INET = user_INET_split[1]
                    pass_INET = request.POST['pass_accout_INET']
                    bw_up_INET = request.POST['bw_up_INET']
                    bw_down_INET = request.POST['bw_down_INET']
                    vport_INET = request.POST['vport_INET'] if 'vport_INET' in request.POST else ''

                    datas.append('###################Configure INTERNET###################')

                    if vendor_code == "fh":
                        for lan in lan_INET:
                            lan_CMD += f'-{lan}'

                        command = f'other|{vendor_code}|{ip_gpon}|{slot}-{port}|{sn};inet|{vlan_INET}|{user_INET}@{domain_INET}|{pass_INET}|{lan_CMD[1:]}|{bw_up_INET}|{bw_down_INET}'
                        log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Configure Internet {vendor_name}", time=datetime.now(), command=command, status='In Progress', message='No Error', logapp=logApp)
                        log.save()

                        if bw_up_INET.upper() == 'BYPASSED' and bw_down_INET.upper() == 'BYPASSED':
                            for lan in lan_INET:
                                cmd = f'SET-WANSERVICE::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn}:5::STATUS=1,MODE=2,CONNTYPE=2,VLAN={vlan_INET},COS={cos_INET},NAT=1,IPMODE=3,PPPOEPROXY=1,PPPOEUSER={user_INET}@{domain_INET},PPPOEPASSWD={pass_INET},PPPOENAME={user_INET},PPPOEMODE=1,UPORT={lan};'
                                tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                                if tl1_cmd['status'] == False:
                                    logAppFailed(logApp.id)

                                    return JsonResponse(
                                        {
                                            'status': tl1_cmd['status'],
                                            'data': tl1_cmd['data']
                                        }
                                    )

                            for ssid in ssid_INET:
                                cmd = f'SET-WANSERVICE::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn}:5::STATUS=1,MODE=2,CONNTYPE=2,VLAN={vlan_INET},COS={cos_INET},NAT=1,IPMODE=3,PPPOEPROXY=1,PPPOEUSER={user_INET}@{domain_INET},PPPOEPASSWD={pass_INET},PPPOENAME={user_INET},PPPOEMODE=1,SSID={ssid};'
                                tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                                if tl1_cmd['status'] == False:
                                    logAppFailed(logApp.id)

                                    return JsonResponse(
                                        {
                                            'status': tl1_cmd['status'],
                                            'data': tl1_cmd['data']
                                        }
                                    )

                        else:
                            for lan in lan_INET:
                                cmd = f'SET-WANSERVICE::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn}:5::STATUS=1,MODE=2,CONNTYPE=2,VLAN={vlan_INET},COS={cos_INET},NAT=1,IPMODE=3,PPPOEPROXY=1,PPPOEUSER={user_INET}@{domain_INET},PPPOEPASSWD={pass_INET},PPPOENAME={user_INET},PPPOEMODE=1,UPORT={lan},UPPROFILENAME=UP-{bw_up_INET},DOWNPROFILENAME=DOWN-{bw_down_INET};'
                                tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                                if tl1_cmd['status'] == False:
                                    logAppFailed(logApp.id)

                                    return JsonResponse(
                                        {
                                            'status': tl1_cmd['status'],
                                            'data': tl1_cmd['data']
                                        }
                                    )

                            for ssid in ssid_INET:
                                cmd = f'SET-WANSERVICE::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn}:5::STATUS=1,MODE=2,CONNTYPE=2,VLAN={vlan_INET},COS={cos_INET},NAT=1,IPMODE=3,PPPOEPROXY=1,PPPOEUSER={user_INET}@{domain_INET},PPPOEPASSWD={pass_INET},PPPOENAME={user_INET},PPPOEMODE=1,SSID={ssid},UPPROFILENAME=UP-{bw_up_INET},DOWNPROFILENAME=DOWN-{bw_down_INET};'
                                tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                                if tl1_cmd['status'] == False:
                                    logAppFailed(logApp.id)

                                    return JsonResponse(
                                        {
                                            'status': tl1_cmd['status'],
                                            'data': tl1_cmd['data']
                                        }
                                    )

                    else:
                        command = f'other|{vendor_code}|{ip_gpon}|{slot}-{port}|{sn};inet|{vlan_INET}|{user_INET}@{domain_INET}|{pass_INET}|{vport_INET}|{bw_up_INET}|{bw_down_INET}'
                        log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action="Configure Internet", time=datetime.now(), command=command, status='In Progress', message='No Error', logapp=logApp)
                        log.save()

                        cmd = f'ADD-PONVLAN::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn}:5::CVLAN={vlan_INET},UV={vlan_INET},SERVICENAME=SPEEDY;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'CFG-ONUBW::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn}:5::UPBW=UP-{bw_up_INET},DOWNBW=DOWN-{bw_down_INET},SERVICENAME=SPEEDY;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'CHG-PORTLOCATING::DID={ip_gpon},OID={sn}:5::VIFID={vport_INET},FORMAT=dsl-forum;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'CHG-PORT-PPPOEPLUS::DID={ip_gpon},OID={sn}:5::VIFID={vport_INET},STATUS=enable;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'CHG-ONUWANIP::DID={ip_gpon},OID={sn}:5::IPHOSTID=1,PPPOEUSER={user_INET}@{domain_INET},PPPOEPWD={pass_INET},VID={vlan_INET};'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )
                        
                        cmd = f'CHG-ONUWAN::DID={ip_gpon},OID={sn}:5::WANID=1,IPHOSTID=1,SERVICETYPE=Internet;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                if service == "WIFIID":
                    vlan_WIFIID = request.POST['vlan_WIFIID']
                    lan_WIFIID = request.POST.getlist('lan_WIFIID')
                    lan_CMD = ''
                    bw_up_WIFIID = request.POST['bw_up_WIFIID']
                    bw_down_WIFIID = request.POST['bw_down_WIFIID']

                    datas.append(f'###################Configure {service}###################')

                    for lan in lan_WIFIID:
                        lan_CMD += f'-{lan}'
                        
                    if vendor_code == "fh":
                        command = f'other|{vendor_code}|{ip_gpon}|{slot}-{port}|{sn};wifiid|{lan_CMD[1:]}|{vlan_WIFIID}'
                        log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Configure {service} {vendor_name}", time=datetime.now(), command=command, status='In Progress', message='No Error', logapp=logApp)
                        log.save()

                        for lan in lan_WIFIID:
                            cmd = f'CFG-LANPORTVLAN::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn},ONUPORT=1-1-1-{lan}:5::CVLAN={vlan_WIFIID},CCOS=1;'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                    else:
                        command = f'other|{vendor_code}|{ip_gpon}|{slot}-{port}|{sn};wifiid|{lan_CMD[1:]}|{vlan_WIFIID}|{bw_up_WIFIID}|{bw_down_WIFIID}'
                        log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Configure {service} {vendor_name}", time=datetime.now(), command=command, status='In Progress', message='No Error', logapp=logApp)
                        log.save()

                        cmd = f'ADD-PONVLAN::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn}:5::CVLAN={vlan_WIFIID},UV={vlan_WIFIID},SERVICENAME={service};'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'CFG-ONUBW::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn}:5::UPBW=UP-{bw_up_WIFIID},DOWNBW=DOWN-{bw_down_WIFIID},SERVICENAME={service};'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        for lan in lan_WIFIID:
                            cmd = f'CFG-LANPORT::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn},ONUPORT=1-1-1-{lan}:5::VLANMOD=Hybrid,PVID={vlan_WIFIID};'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                            cmd = f'CHG-ONUUNI-PON::DID={ip_gpon},OID={sn},ONUPORT={lan}:5::IPRETRIEVEMODE=FromNetwork;'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                if service == "ASTINET":
                    vlan_ASTINET = request.POST['vlan_ASTINET']
                    lan_ASTINET = request.POST.getlist('lan_ASTINET')
                    lan_CMD = ''
                    bw_up_ASTINET = request.POST['bw_up_ASTINET']
                    bw_down_ASTINET = request.POST['bw_down_ASTINET']

                    datas.append(f'###################Configure {service}###################')

                    for lan in lan_ASTINET:
                        lan_CMD += f'-{lan}'

                    if vendor_code == "fh":
                        command = f'other|{vendor_code}|{ip_gpon}|{slot}-{port}|{sn};astinet|{lan_CMD[1:]}|{vlan_ASTINET}'
                        log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Configure {service} {vendor_name}", time=datetime.now(), command=command, status='In Progress', message='No Error', logapp=logApp)
                        log.save()

                        for lan in lan_ASTINET:
                            cmd = f'CFG-LANPORTVLAN::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn},ONUPORT=1-1-1-{lan}:5::CVLAN={vlan_ASTINET},CCOS=1;'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )
                            
                    else:
                        command = f'other|{vendor_code}|{ip_gpon}|{slot}-{port}|{sn};astinet|{lan_CMD[1:]}|{vlan_ASTINET}|{bw_up_ASTINET}|{bw_down_ASTINET}'
                        log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Configure {service} {vendor_name}", time=datetime.now(), command=command, status='In Progress', message='No Error', logapp=logApp)
                        log.save()

                        cmd = f'ADD-PONVLAN::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn}:5::CVLAN={vlan_ASTINET},UV={vlan_ASTINET},SERVICENAME={service};'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'CFG-ONUBW::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn}:5::UPBW=UP-{bw_up_ASTINET},DOWNBW=DOWN-{bw_down_ASTINET},SERVICENAME={service};'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        for lan in lan_ASTINET:
                            cmd = f'CFG-LANPORT::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn},ONUPORT=1-1-1-{lan}:5::VLANMOD=Hybrid,PVID={vlan_ASTINET};'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                if service == "VPNIP":
                    vlan_VPNIP = request.POST['vlan_VPNIP']
                    lan_VPNIP = request.POST.getlist('lan_VPNIP')
                    lan_CMD = ''
                    bw_up_VPNIP = request.POST['bw_up_VPNIP']
                    bw_down_VPNIP = request.POST['bw_down_VPNIP']

                    datas.append(f'###################Configure {service}###################')

                    for lan in lan_VPNIP:
                        lan_CMD += f'-{lan}'

                    if vendor_code == "fh":
                        command = f'other|{vendor_code}|{ip_gpon}|{slot}-{port}|{sn};vpnip|{lan_CMD[1:]}|{vlan_VPNIP}'
                        log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Configure {service} {vendor_name}", time=datetime.now(), command=command, status='In Progress', message='No Error', logapp=logApp)
                        log.save()

                        for lan in lan_VPNIP:
                            cmd = f'CFG-LANPORTVLAN::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn},ONUPORT=1-1-1-{lan}:5::CVLAN={vlan_VPNIP},CCOS=1;'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                    else:
                        command = f'other|{vendor_code}|{ip_gpon}|{slot}-{port}|{sn};vpnip|{lan_CMD[1:]}|{vlan_VPNIP}|{bw_up_VPNIP}|{bw_down_VPNIP}'
                        log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Configure {service} {vendor_name}", time=datetime.now(), command=command, status='In Progress', message='No Error', logapp=logApp)
                        log.save()

                        cmd = f'ADD-PONVLAN::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn}:5::CVLAN={vlan_VPNIP},UV={vlan_VPNIP},SERVICENAME={service};'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )
                        
                        cmd = f'CFG-ONUBW::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn}:5::UPBW=UP-{bw_up_VPNIP},DOWNBW=DOWN-{bw_down_VPNIP},SERVICENAME={service};'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        for lan in lan_VPNIP:
                            cmd = f'CFG-LANPORT::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn},ONUPORT=1-1-1-{lan}:5::VLANMOD=Hybrid,PVID={vlan_VPNIP};'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

        if create_ont == "Modify ONT" and action == "Delete" :
            for service in services:
                if service == "IPTV":
                    lan_IPTV = request.POST.getlist('lan_IPTV')
                    lan_CMD = ''

                    datas.append(f'###################Delete {service}###################')
                    
                    for lan in lan_IPTV:
                        lan_CMD += f'-{lan}'

                    command = f'other|{vendor_code}|{ip_gpon}|{slot}-{port}|{sn};iptv|{lan_CMD[1:]}'
                    log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Delete Service {service} {vendor_name}", time=datetime.now(), command=command, status='In Progress', message='No Error', logapp=logApp)
                    log.save()

                    if vendor_code == "fh":
                        for lan in lan_IPTV:
                            cmd = f'DEL-LANIPTVPORT::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn},ONUPORT=1-1-1-{lan}:5::MVLAN=110;'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                            cmd = f'DEL-LANPORTVLAN::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn},ONUPORT=1-1-1-{lan}:5::UV=111;'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                    else:
                        for lan in lan_IPTV:
                            cmd = f'CHG-ONUUNI-PON::DID={ip_gpon},OID={sn},ONUPORT={lan}:5::IPRETRIEVEMODE=NoControl;'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                            cmd = f'CFG-LANPORT::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn},ONUPORT=1-1-1-{lan}:5::VLANMOD=None;'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                            cmd = f'DEL-LANIPTVPORT::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn},ONUPORT=1-1-1-{lan}:5::MVLAN=110;'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                        cmd = f'DEL-PONVLAN::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn}:5::CVLAN=111,UV=111,SERVICENAME=USEETV;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                if service == "VOICE":
                    vlan_VOICE = request.POST['vlan_VOICE']
                    pots = request.POST['lan_VOICE']
                    vport_VOICE = request.POST['vport_VOICE'] if 'vport_VOICE' in request.POST else ''

                    datas.append(f'###################Delete {service}###################')
                    
                    if vendor_code == "fh":
                        command = f'other|{vendor_code}|{ip_gpon}|{slot}-{port}|{sn};voice'
                        log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Configure {service} {vendor_name}", time=datetime.now(), command=command, logapp=logApp)
                        log.save()

                        cmd = f'DEL-VOIPSERVICE::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn},ONUPORT=1-1-1-{pots}:5::;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                    else:
                        command = f'other|{vendor_code}|{ip_gpon}|{slot}-{port}|{sn};voice|{vlan_VOICE}'
                        log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Configure {service} {vendor_name}", time=datetime.now(), command=command, logapp=logApp)
                        log.save()

                        cmd = f'DEL-VOIPSERVICE::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn},ONUPORT=1-1-1-{pots}:::;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'CHG-PORT-DHCP::DID={ip_gpon},OID={sn}:5::VIFID={vport_VOICE},OPTION82STAT=Disable;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'DEL-PONVLAN::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn}:5::CVLAN={vlan_VOICE},UV={vlan_VOICE},SERVICENAME=VOIP;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                if service == "INET":
                    vlan_INET = request.POST['vlan_INET']
                    cos_INET = request.POST['cos_INET'] if 'cos_INET' in request.POST else ''
                    lan_INET = request.POST.getlist('lan_INET') if 'lan_INET' in request.POST else ''
                    lan_CMD = ''
                    ssid_INET = request.POST.getlist('ssid_INET') if 'ssid_INET' in request.POST else ''
                    vport_INET = request.POST['vport_INET'] if 'vport_INET' in request.POST else ''
                    user_INET_split = request.POST['user_accout_INET'].split('@')
                    user_INET = user_INET_split[0]
                    domain_INET = user_INET_split[1]
                    pass_INET = request.POST['pass_accout_INET']

                    datas.append('###################Delete INTERNET###################')

                    if vendor_code == "fh":
                        for lan in lan_INET:
                            lan_CMD += f'-{lan}'

                        command = f'other|{vendor_code}|{ip_gpon}|{slot}-{port}|{sn};inet|{vlan_INET}|{lan_CMD[1:]}'
                        log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Delete Service Internet {vendor_name}", time=datetime.now(), command=command, status='In Progress', message='No Error', logapp=logApp)
                        log.save()

                        for lan in lan_INET:
                            cmd = f'SET-WANSERVICE::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn}:5::STATUS=2,MODE=2,CONNTYPE=2,VLAN={vlan_INET},COS={cos_INET},NAT=1,IPMODE=3,PPPOEPROXY=1,PPPOEUSER={user_INET}@{domain_INET},PPPOEPASSWD={pass_INET},PPPOENAME={user_INET},PPPOEMODE=1,UPORT={lan};'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                        for ssid in ssid_INET:
                            cmd = f'SET-WANSERVICE::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn}:5::STATUS=2,MODE=2,CONNTYPE=2,VLAN={vlan_INET},COS={cos_INET},NAT=1,IPMODE=3,PPPOEPROXY=1,PPPOEUSER={user_INET}@{domain_INET},PPPOEPASSWD={pass_INET},PPPOENAME={user_INET},PPPOEMODE=1,SSID={ssid};'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                    else:
                        command = f'other|{vendor_code}|{ip_gpon}|{slot}-{port}|{sn};inet|{vlan_INET}'
                        log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Delete Service Internet {vendor_name}", time=datetime.now(), command=command, status='In Progress', message='No Error', logapp=logApp)
                        log.save()

                        cmd = f'DLT-ONUWAN::DID={ip_gpon},OID={sn}:5::WANID=1,IPHOSTID=1;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'DLT-ONUWANIP::DID={ip_gpon},OID={sn}:5::IPHOSTID=1;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'CHG-PORT-PPPOEPLUS::DID={ip_gpon},OID={sn}:5::VIFID={vport_INET},STATUS=disable;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                              
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'DEL-PONVLAN::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn}:5::CVLAN={vlan_INET},UV={vlan_INET},SERVICENAME=SPEEDY;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                if service == "WIFIID":
                    vlan_WIFIID = request.POST['vlan_WIFIID']
                    lan_WIFIID = request.POST.getlist('lan_WIFIID')
                    lan_CMD = ''

                    datas.append(f'###################Delete {service}###################')

                    for lan in lan_WIFIID:
                        lan_CMD += f'-{lan}'

                    command = f'other|{vendor_code}|{ip_gpon}|{slot}-{port}|{sn};wifiid|{lan_CMD[1:]}|{vlan_WIFIID}'
                    log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Delete Service {service} {vendor_name}", time=datetime.now(), command=command, logapp=logApp)
                    log.save()
                    
                    if vendor_code == "fh":
                        for lan in lan_WIFIID:
                            cmd = f'DEL-LANPORTVLAN::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn},ONUPORT=1-1-1-{lan}:5::UV={vlan_WIFIID};'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                    else:
                        for lan in lan_WIFIID:
                            cmd = f'CHG-ONUUNI-PON::DID={ip_gpon},OID={sn},ONUPORT={lan}:5::IPRETRIEVEMODE=NoControl;'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                            cmd = f'CFG-LANPORT::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn},ONUPORT=1-1-1-{lan}:5::VLANMOD=None;'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                        cmd = f'DEL-PONVLAN::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn}:5::CVLAN={vlan_WIFIID},UV={vlan_WIFIID},SERVICENAME={service};'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                if service == "ASTINET":
                    vlan_ASTINET = request.POST['vlan_ASTINET']
                    lan_ASTINET = request.POST.getlist('lan_ASTINET')
                    lan_CMD = ''

                    datas.append(f'###################Delete {service}###################')

                    for lan in lan_ASTINET:
                        lan_CMD += f'-{lan}'

                    command = f'other|{vendor_code}|{ip_gpon}|{slot}-{port}|{sn};astinet|{lan_CMD[1:]}|{vlan_ASTINET}'
                    log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Delete Service {service} {vendor_name}", time=datetime.now(), command=command, logapp=logApp)
                    log.save()

                    if vendor_code == "fh":
                        for lan in lan_ASTINET:
                            cmd = f'DEL-LANPORTVLAN::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn},ONUPORT=1-1-1-{lan}:5::UV={vlan_ASTINET};'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                    else:
                        for lan in lan_ASTINET:
                            cmd = f'CFG-LANPORT::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn},ONUPORT=1-1-1-{lan}:5::VLANMOD=None;'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                        cmd = f'DEL-PONVLAN::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn}:5::CVLAN={vlan_ASTINET},UV={vlan_ASTINET},SERVICENAME={service};'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                if service == "VPNIP":
                    vlan_VPNIP = request.POST['vlan_VPNIP']
                    lan_VPNIP = request.POST.getlist('lan_VPNIP')
                    lan_CMD = ''

                    datas.append(f'###################Delete {service}###################')

                    for lan in lan_VPNIP:
                        lan_CMD += f'-{lan}'

                    command = f'other|{vendor_code}|{ip_gpon}|{slot}-{port}|{sn};vpnip|{lan_CMD[1:]}|{vlan_VPNIP}'
                    log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Delete Service {service} {vendor_name}", time=datetime.now(), command=command, status='In Progress', message='No Error', logapp=logApp)
                    log.save()

                    if vendor_code == "fh":
                        for lan in lan_VPNIP:
                            cmd = f'DEL-LANPORTVLAN::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=MAC,ONUID={sn},ONUPORT=1-1-1-{lan}:5::UV={vlan_VPNIP};'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                    else:
                        for lan in lan_VPNIP:
                            cmd = f'CFG-LANPORT::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn},ONUPORT=1-1-1-{lan}:5::VLANMOD=None;'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )



                        cmd = f'DEL-PONVLAN::OLTID={ip_gpon},PONID=1-1-{slot}-{port},ONUIDTYPE=SN,ONUID={sn}:5::CVLAN={vlan_VPNIP},UV={vlan_VPNIP},SERVICENAME={service};'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

        s.close()
        logAppSuccess(logApp.id)
        datas = '\n'.join(datas)
        request.session['hasil'] = datas
        request.session['hw'] = False
        return JsonResponse(
            {
                'status': True,
            }
        )

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
@user_passes_test(check_permissions)
def config_batch(request):
    if session_login(request) == 'zero':
        return redirect('login:formOtp')

    page_title = 'CONFIG BATCH'

    if request.method == "POST":
        datas = []
        data = request.POST['cmd_gpon'].splitlines()

        list_np = []
        logApp = logAppIn(request, page_title, f'{page_title} NMS')

        for data1 in data:

            data_dump1 = data1.split(';')
            data_dump2 = data_dump1[0].split('|')
            tl1 = ServerTl1.objects.get(server_gpon__ip_gpon=data_dump2[2])
            ip_server = tl1.ip_server
            port_tl1 = tl1.port_tl1
            s = socket(AF_INET, SOCK_STREAM)
            s.connect((ip_server, port_tl1))

            if data_dump2[1].upper() == "FH":
                cmd_login = f'LOGIN:::CTAG::UN={tl1.user_tl1},PWD={tl1.pass_tl1};'
                s.send(cmd_login.encode())
                time.sleep(2)

            ip_gpon = data_dump2[2]
            slot_port = data_dump2[3].split('-')
            slot = slot_port[0]
            port = slot_port[1]
            sn = data_dump2[4]

            list_np.append(ip_server)
            np_array = np.array(list_np)
            ip_servers = ', '.join(np.unique(np_array))
            target = f'{page_title} NMS: {ip_servers}'
            logAppUpdate = LogApp.objects.get(pk=logApp.id)
            logAppUpdate.target = target
            logAppUpdate.save()

            datas.append(f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}\n")
            data_ip_port = []
            cmd_ip = []
            cmd_ont = None

            for data2 in data1.split(';'):
                data3 = data2.split('|')
                if data3[0].upper() == "ONT":
                    datas.append("=================CREATE ONT=================")
                    if data3[1].upper() == "FH" or data3[1] == "fh":
                        if len(data3) > 6:
                            cmd_option = f'AUTHTYPE=MAC,ONUID={data3[4]},ONUTYPE={data3[5].upper()},NAME={data3[6]} | {data3[4]};'
                        elif len(data3) > 5:
                            cmd_option = f'AUTHTYPE=MAC,ONUID={data3[4]},ONUTYPE={data3[5].upper()};'
                        else:
                            cmd_option = f'AUTHTYPE=MAC,ONUID={data3[4]},ONUTYPE=AN5506-04-F1;'
                        onuidtype = "MAC"
                    else:
                        if len(data3) > 6:
                            cmd_option = f'AUTHTYPE=SN,ONUID={data3[4]},ONUTYPE={data3[5].upper()},NAME={data3[6]}|{data3[4]};'
                        elif len(data3) > 5:
                            cmd_option = f'AUTHTYPE=SN,ONUID={data3[4]},ONUTYPE={data3[5].upper()};'
                        else:
                            cmd_option = f'AUTHTYPE=SN,ONUID={data3[4]},ONUTYPE=ZTEG-F609;'
                        onuidtype = "SN"

                    data_ip_port.append(data3[2].upper())
                    data_ip_port.append(data3[3].upper())
                    data_ip_port.append(onuidtype)
                    data_ip_port.append(data3[4].upper())
                    data_ip_port.append(data3[1])

                    log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action="Register ONT", time=datetime.now(), command=data2, status='In Progress', message='No Error', logapp=logApp)
                    log.save()

                    cmd = f'ADD-ONU::OLTID={data_ip_port[0]},PONID=1-1-{data_ip_port[1]}:::{cmd_option}'
                    tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                    if tl1_cmd['status'] == False:
                        logAppFailed(logApp.id)
                        
                        return JsonResponse(
                            {
                                'status': tl1_cmd['status'],
                                'data': tl1_cmd['data']
                            }
                        )

                    cmd_ont = f'other|{ip_gpon}|{slot}-{port}|{sn}'

                    cmd_fhzte = f'OLTID={data_ip_port[0]},PONID=1-1-{data_ip_port[1]},ONUIDTYPE={onuidtype},ONUID={data_ip_port[3]}'
                    cmd_zte = f'DID={data_ip_port[0]},OID={data_ip_port[3]}'

                    cmd_ip.append(cmd_fhzte)
                    cmd_ip.append(cmd_zte)

                elif data3[0].upper() == "OTHER":
                    if data3[1].upper() == "FH" or data3[1] == "fh":
                        onuidtype = "MAC"
                    else:
                        onuidtype = "SN"

                    data_ip_port.append(data3[2].upper())
                    data_ip_port.append(data3[3].upper())
                    data_ip_port.append(onuidtype)
                    data_ip_port.append(data3[4].upper())
                    data_ip_port.append(data3[1])

                    cmd_fhzte = f'OLTID={data_ip_port[0]},PONID=1-1-{data_ip_port[1]},ONUIDTYPE={onuidtype},ONUID={data_ip_port[3]}'
                    cmd_zte = f'DID={data_ip_port[0]},OID={data_ip_port[3]}'
                    cmd_ont = data2

                    cmd_ip.append(cmd_fhzte)
                    cmd_ip.append(cmd_zte)

                if data3[0].upper() == "INET":
                    datas.append("=================INTERNET=================")
                    log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action="Configure Internet", time=datetime.now(), command=f'{cmd_ont};{data2}', status='In Progress', message='No Error', logapp=logApp)
                    log.save()

                    if data_ip_port[4].upper() == "FH" or data_ip_port[4].upper() == "fh":
                        if (len(data3) > 5):
                            cmd_bw = f'UPPROFILENAME=UP-{data3[4]},DOWNPROFILENAME=DOWN-{data3[5]};'
                        else:
                            cmd_bw = 'UPPROFILENAME=UP-2253KB0,DOWNPROFILENAME=DOWN-11264KB0;'

                        userAccount = data3[2].split('@')
                        cmd = f'SET-WANSERVICE::{cmd_ip[0]}:5::STATUS=1,MODE=2,CONNTYPE=2,VLAN={data3[1]},COS=0,NAT=1,IPMODE=3,PPPOEPROXY=1,PPPOEUSER={data3[2]},PPPOEPASSWD={data3[3]},PPPOENAME={userAccount[0]},PPPOEMODE=1,UPORT=3,{cmd_bw}'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)

                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'SET-WANSERVICE::{cmd_ip[0]}:5::STATUS=1,MODE=2,CONNTYPE=2,VLAN={data3[1]},COS=0,NAT=1,IPMODE=3,PPPOEPROXY=1,PPPOEUSER={data3[2]},PPPOEPASSWD={data3[3]},PPPOENAME={userAccount[0]},PPPOEMODE=1,SSID=1,{cmd_bw}'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                    else:
                        if (len(data3) > 6):
                            vport = data3[4]
                            up_bw = f'UP-{data3[5]}'
                            down_bw = f'DOWN-{data3[6]}'
                        elif (len(data3) > 4):
                            vport = data3[4]
                            up_bw = 'UP-2253KB0'
                            down_bw = 'DOWN-11264KB0'
                        else:
                            vport = '3'
                            up_bw = 'UP-2253KB0'
                            down_bw = 'DOWN-11264KB0'

                        cmd = f'ADD-PONVLAN::{cmd_ip[0]}:5::CVLAN={data3[1]},UV={data3[1]},SERVICENAME=SPEEDY;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'CFG-ONUBW::{cmd_ip[0]}:::UPBW={up_bw},DOWNBW={down_bw},SERVICENAME=SPEEDY;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'CHG-PORTLOCATING::{cmd_ip[1]}:::VIFID={vport},FORMAT=dsl-forum;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'CHG-PORT-PPPOEPLUS::{cmd_ip[1]}:::VIFID={vport},STATUS=enable;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'CHG-ONUWANIP::{cmd_ip[1]}:::IPHOSTID=1,PPPOEUSER={data3[2]},PPPOEPWD={data3[3]},VID={data3[1]};'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'CHG-ONUWAN::{cmd_ip[1]}:::WANID=1,IPHOSTID=1,SERVICETYPE=Internet;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                if data3[0].upper() == "VOICE":
                    datas.append("=================VOICE=================")
                    log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action="Configure VOICE", time=datetime.now(), command=f'{cmd_ont};{data2}', status='In Progress', message='No Error', logapp=logApp)
                    log.save()

                    if data_ip_port[4].upper() == "FH" or data_ip_port[4].upper() == "fh":
                        cmd = f'CFG-VOIPSERVICE::{cmd_ip[0]},ONUPORT=1-1-1-1:5::PHONENUMBER={data3[2]},PT=SIP,VOIPVLAN={data3[1]},SCOS=7,EID=@telkom.net.id,SIPUSERNAME={data3[2]},SIPUSERPWD={data3[3]},IPMODE=DHCP;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                    else:
                        if (len(data3) > 4):
                            vport = data3[4]
                        else:
                            vport = '2'

                        cmd = f'ADD-PONVLAN::{cmd_ip[0]}:5::CVLAN={data3[1]},UV={data3[1]},SERVICENAME=VOICE;\n'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'CFG-ONUBW::{cmd_ip[0]}:::UPBW=UP-1M,DOWNBW=DOWN-1M,SERVICENAME=VOICE;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'CHG-PORT-DHCP::{cmd_ip[1]}:::VIFID={vport},OPTION82STAT=Enable;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'CFG-VOIPSERVICE::{cmd_ip[0]},ONUPORT=1-1-1-1:::PT=SIP,PHONENUMBER={data3[2]},SIPREGDM="10.0.0.10::10.0.0.40",SIPUSERNAME={data3[2]}@telkom.net.id,SIPUSERPWD={data3[3]},VOIPVLAN={data3[1]},CCOS=0,IPMODE=DHCP,IPHOSTID=2;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                if data3[0].upper() == "IPTV" or data3[0].upper() == "WIFIID" or data3[0].upper() == "ASTINET" or data3[0].upper() == "VPNIP":
                    datas.append(f"================={data3[0].upper()}=================")
                    log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action=f"Configure {data3[0].upper()}", time=datetime.now(), command=f'{cmd_ont};{data2}', status='In Progress', message='No Error', logapp=logApp)
                    log.save()

                    port_lan = []
                    if len(data3) > 1:
                        for lan in data3[1].split('-'):
                            port_lan.append(lan)
                    else:
                        lan = '4'
                        port_lan.append(lan)

                    if len(data3) > 4:
                        up_bw = data3[3]
                        down_bw = data3[4]
                        bw_lan = f'BW={up_bw}_{down_bw}'
                    else:
                        up_bw = "2253KA4"
                        down_bw = "9012KA4"
                        bw_lan = ';'

                    if data_ip_port[4].upper() == "FH" or data_ip_port[4].upper() == "fh":
                        for onuport in port_lan:
                            if data3[0].upper() == "IPTV":
                                cmd = f'ADD-LANIPTVPORT::{cmd_ip[0]},ONUPORT=1-1-1-{onuport}:5::MVLAN=110,MCOS=4;'
                                tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                                if tl1_cmd['status'] == False:
                                    logAppFailed(logApp.id)
                                    
                                    return JsonResponse(
                                        {
                                            'status': tl1_cmd['status'],
                                            'data': tl1_cmd['data']
                                        }
                                    )

                                cmd = f'CFG-LANPORTVLAN::{cmd_ip[0]},ONUPORT=1-1-1-{onuport}:5::CVLAN=111,CCOS=4;'
                                tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                                if tl1_cmd['status'] == False:
                                    logAppFailed(logApp.id)
                                    
                                    return JsonResponse(
                                        {
                                            'status': tl1_cmd['status'],
                                            'data': tl1_cmd['data']
                                        }
                                    )

                                cmd = f'CFG-LANPORT::{cmd_ip[0]},ONUPORT=1-1-1-{onuport}:5::BW=DOWN8MKA4_UP2253KA4;'
                                tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                                if tl1_cmd['status'] == False:
                                    logAppFailed(logApp.id)
                                    
                                    return JsonResponse(
                                        {
                                            'status': tl1_cmd['status'],
                                            'data': tl1_cmd['data']
                                        }
                                    )

                            if data3[0].upper() != "IPTV":
                                cmd = f'CFG-LANPORTVLAN::{cmd_ip[0]},ONUPORT=1-1-1-{onuport}:5::CVLAN={data3[2]},CCOS=4;'
                                tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                                if tl1_cmd['status'] == False:
                                    logAppFailed(logApp.id)
                                    
                                    return JsonResponse(
                                        {
                                            'status': tl1_cmd['status'],
                                            'data': tl1_cmd['data']
                                        }
                                    )

                                cmd = f'CFG-LANPORT::{cmd_ip[0]},ONUPORT=1-1-1-{onuport}:5::{bw_lan}'
                                tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                                if tl1_cmd['status'] == False:
                                    logAppFailed(logApp.id)
                                    
                                    return JsonResponse(
                                        {
                                            'status': tl1_cmd['status'],
                                            'data': tl1_cmd['data']
                                        }
                                    )

                    else:
                        if data3[0].upper() == "IPTV":
                            cmd = f'ADD-PONVLAN::{cmd_ip[0]}:::CVLAN=111,UV=111,SERVICENAME=USEETV;'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                            cmd = f'CFG-ONUBW::{cmd_ip[0]}:::UPBW=UP-2253KA4,DOWNBW=DOWN-9012KA4,SERVICENAME=USEETV;'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                        else:
                            cmd = f'ADD-PONVLAN::{cmd_ip[0]}:::CVLAN={data3[2]},UV={data3[2]},SERVICENAME={data3[0].upper()};'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                            cmd = f'CFG-ONUBW::{cmd_ip[0]}:::UPBW=UP-{up_bw},DOWNBW=DOWN-{down_bw},SERVICENAME={data3[0].upper()};'
                            tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                            if tl1_cmd['status'] == False:
                                logAppFailed(logApp.id)
                                
                                return JsonResponse(
                                    {
                                        'status': tl1_cmd['status'],
                                        'data': tl1_cmd['data']
                                    }
                                )

                        for onuport in port_lan:
                            if data3[0].upper() == "IPTV":
                                cmd = f'ADD-LANIPTVPORT::{cmd_ip[0]},ONUPORT=1-1-1-{onuport}:::MVLAN=110,SERVICENAME=USEETV;'
                                tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                                if tl1_cmd['status'] == False:
                                    logAppFailed(logApp.id)
                                    
                                    return JsonResponse(
                                        {
                                            'status': tl1_cmd['status'],
                                            'data': tl1_cmd['data']
                                        }
                                    )

                                cmd = f'CFG-LANPORT::{cmd_ip[0]},ONUPORT=1-1-1-{onuport}:::VLANMOD=Hybrid,PVID=111;'
                                tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                                if tl1_cmd['status'] == False:
                                    logAppFailed(logApp.id)
                                    
                                    return JsonResponse(
                                        {
                                            'status': tl1_cmd['status'],
                                            'data': tl1_cmd['data']
                                        }
                                    )

                                cmd = f'CHG-ONUUNI-PON::{cmd_ip[1]},ONUPORT={onuport}:::IPRETRIEVEMODE=FromNetwork;'
                                tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                                if tl1_cmd['status'] == False:
                                    logAppFailed(logApp.id)
                                    
                                    return JsonResponse(
                                        {
                                            'status': tl1_cmd['status'],
                                            'data': tl1_cmd['data']
                                        }
                                    )

                            elif data3[0].upper() == "WIFIID":
                                cmd = f'CFG-LANPORT::{cmd_ip[0]},ONUPORT=1-1-1-{onuport}:::VLANMOD=Hybrid,PVID={data3[2]};'
                                tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                                if tl1_cmd['status'] == False:
                                    logAppFailed(logApp.id)
                                    
                                    return JsonResponse(
                                        {
                                            'status': tl1_cmd['status'],
                                            'data': tl1_cmd['data']
                                        }
                                    )

                                cmd = f'CHG-ONUUNI-PON::{cmd_ip[1]},ONUPORT={onuport}:::IPRETRIEVEMODE=FromNetwork;'
                                tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                                if tl1_cmd['status'] == False:
                                    logAppFailed(logApp.id)
                                    
                                    return JsonResponse(
                                        {
                                            'status': tl1_cmd['status'],
                                            'data': tl1_cmd['data']
                                        }
                                    )

                            else:
                                cmd = f'CFG-LANPORT::{cmd_ip[0]},ONUPORT=1-1-1-{onuport}:::VLANMOD=Hybrid,PVID={data3[2]};'
                                tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                                if tl1_cmd['status'] == False:
                                    logAppFailed(logApp.id)
                                    
                                    return JsonResponse(
                                        {
                                            'status': tl1_cmd['status'],
                                            'data': tl1_cmd['data']
                                        }
                                    )

            if data_dump2[1].upper() == "FH":
                s.send(b'LOGOUT:::5::;')
                time.sleep(2)

            s.close()

            logAppSuccess(logApp.id)

        datas = '\n'.join(datas)
        request.session['hasil'] = datas
        request.session['hw'] = False
        return JsonResponse(
            {
                'status': True,
            }
        )
    else:
        vendor = ServerTl1.objects.values('vendor').order_by('vendor').annotate(vcount=Count('vendor'))

        placeholder = "Contoh Fiberhome :\n"
        placeholder += "=====CREATE ONT==========\n"
        placeholder += "ont|fh|172.29.215.6|6-6|FHTT06138248\n"
        placeholder += "ont|fh|172.29.215.6|6-6|FHTT06138248|HG6243C\n"
        placeholder += "ont|fh|172.29.215.6|6-6|FHTT06138248|HG6243C|{NAMA_PELANGGAN}\n"
        placeholder += "=====CREATE INTERNET==========\n"
        placeholder += "other|fh|172.29.215.6|6-6|FHTT06138248;INET|1904|131626153157@telkom.net|707341163\n"
        placeholder += "other|fh|172.29.215.6|6-6|FHTT06138248;INET|1904|131626153157@telkom.net|707341163|1536K|15360K\n"
        placeholder += "=====CREATE VOICE==========\n"
        placeholder += "other|fh|172.29.215.6|6-6|FHTT06138248;VOICE|532|+622666221191|190718488\n"
        placeholder += "=====CREATE IPTV==========\n"
        placeholder += "other|fh|172.29.215.6|6-6|FHTT06138248;IPTV\n"
        placeholder += "=====CREATE 3P/2P/1P + ONT==========\n"
        placeholder += "ont|fh|172.29.215.6|6-6|FHTT06138248|HG6243C|NAMA_PELANGGAN;INET|1904|131626153157@telkom.net|707341163|1536K|15360K;VOICE|532|+622666221191|190718488;IPTV\n"
        placeholder += "\n"
        placeholder += "\n"
        placeholder += "Contoh ZTE :\n"
        placeholder += "=====CREATE ONT==========\n"
        placeholder += "ont|zte|172.21.202.4|12-2|ZTEGC6753017\n"
        placeholder += "ont|zte|172.21.202.4|12-2|ZTEGC6753017|ZTEG-F609\n"
        placeholder += "ont|zte|172.21.202.4|12-2|ZTEGC6753017|ZTEG-F609|NAMA_PELANGGAN\n"
        placeholder += "=====CREATE INTERNET==========\n"
        placeholder += "other|zte|172.21.202.4|12-2|ZTEGC6753017;INET|770|131626153157@telkom.net|707341163|\n"
        placeholder += "other|zte|172.21.202.4|12-2|ZTEGC6753017;INET|770|131626153157@telkom.net|707341163|{vport}\n"
        placeholder += "other|zte|172.21.202.4|12-2|ZTEGC6753017;INET|770|131626153157@telkom.net|707341163|{vport}|1536K|15360K\n"
        placeholder += "=====CREATE VOICE==========\n"
        placeholder += "other|zte|172.21.202.4|12-2|ZTEGC6753017;VOICE|571|+622667121278|9866556\n"
        placeholder += "other|zte|172.21.202.4|12-2|ZTEGC6753017;VOICE|571|+622667121278|9866556|{vport}\n"
        placeholder += "=====CREATE IPTV==========\n"
        placeholder += "other|zte|172.21.202.4|12-2|ZTEGC6753017;IPTV\n"
        placeholder += "=====CREATE 3P/2P/1P + ONT==========\n"
        placeholder += "ont|zte|172.21.202.4|12-2|ZTEGC6753017|ZTEG-F609|NAMA_PELANGGAN;INET|770|131626153157@telkom.net|707341163|1|1536K|15360K;VOICE|571|+622667121278|9866556|2;IPTV\n"

        context = {
            'page_title': page_title,
            'vendors': vendor,
            'placeholder': placeholder,
            'client_ip': get_client_ip(request),
        }
        return render(request, 'config.html', context)

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
@user_passes_test(check_permissions)
def delete_config_batch(request):
    if session_login(request) == 'zero':
        return redirect('login:formOtp')

    page_title = 'DELETE BATCH'

    if request.method == "POST":
        datas = []
        data = request.POST['cmd_gpon']

        list_np = []
        logApp = logAppIn(request, page_title, f'{page_title} NMS')

        for data1 in data.splitlines():

            data_dump1 = data1.split(';')
            data_dump2 = data_dump1[0].split('|')
            tl1 = ServerTl1.objects.get(server_gpon__ip_gpon=data_dump2[2])
            ip_server = tl1.ip_server
            port_tl1 = tl1.port_tl1
            s = socket(AF_INET, SOCK_STREAM)
            s.connect((ip_server, port_tl1))

            if data_dump2[1].upper() == "FH":
                cmd_login = f'LOGIN:::CTAG::UN={tl1.user_tl1},PWD={tl1.pass_tl1};'
                s.send(cmd_login.encode())
                time.sleep(2)

            ip_gpon = data_dump2[2]
            slot_port = data_dump2[3].split('-')
            slot = slot_port[0]
            port = slot_port[1]
            sn = data_dump2[4]

            list_np.append(ip_server)
            np_array = np.array(list_np)
            ip_servers = ', '.join(np.unique(np_array))
            target = f'{page_title} NMS: {ip_servers}'
            logAppUpdate = LogApp.objects.get(pk=logApp.id)
            logAppUpdate.target = target
            logAppUpdate.save()

            datas.append(f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}\n")
            data_ip_port = []
            cmd_ip = []
            cmd_ont = None

            for data2 in data1.split(';'):
                data3 = data2.split('|')
                if data3[0].upper() == "ONT":
                    datas.append("=================DELETE ONT=================")
                    if data3[1].upper() == "FH" or data3[1] == "fh":
                        cmd_option = f'ONUIDTYPE=MAC,ONUID={data3[4]};'
                        onuidtype = "MAC"
                    else:
                        cmd_option = f'ONUIDTYPE=SN,ONUID={data3[4]};'
                        onuidtype = "SN"

                    data_ip_port.append(data3[2].upper())
                    data_ip_port.append(data3[3].upper())
                    data_ip_port.append(onuidtype)
                    data_ip_port.append(data3[4].upper())
                    data_ip_port.append(data3[1])

                    log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action="Delete ONT", time=datetime.now(), command=data2, status='In Progress', message='No Error', logapp=logApp)
                    log.save()

                    cmd = f'DEL-ONU::OLTID={data_ip_port[0]},PONID=1-1-{data_ip_port[1]}:::{cmd_option}'
                    tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                    if tl1_cmd['status'] == False:
                        logAppFailed(logApp.id)
                        
                        return JsonResponse(
                            {
                                'status': tl1_cmd['status'],
                                'data': tl1_cmd['data']
                            }
                        )

                    cmd_ont = f'other|{ip_gpon}|{slot}-{port}|{sn}'

                    cmd_fhzte = f'OLTID={data_ip_port[0]},PONID=1-1-{data_ip_port[1]},ONUIDTYPE={onuidtype},ONUID={data_ip_port[3]}'
                    cmd_zte = f'DID={data_ip_port[0]},OID={data_ip_port[3]}'

                    cmd_ip.append(cmd_fhzte)
                    cmd_ip.append(cmd_zte)

                elif data3[0].upper() == "OTHER":
                    if data3[1].upper() == "FH" or data3[1] == "fh":
                        onuidtype = "MAC"
                    else:
                        onuidtype = "SN"

                    data_ip_port.append(data3[2].upper())
                    data_ip_port.append(data3[3].upper())
                    data_ip_port.append(onuidtype)
                    data_ip_port.append(data3[4].upper())
                    data_ip_port.append(data3[1])

                    cmd_ont = data2

                    cmd_fhzte = f'OLTID={data_ip_port[0]},PONID=1-1-{data_ip_port[1]},ONUIDTYPE={onuidtype},ONUID={data_ip_port[3]}'
                    cmd_zte = f'DID={data_ip_port[0]},OID={data_ip_port[3]}'

                    cmd_ip.append(cmd_fhzte)
                    cmd_ip.append(cmd_zte)

                if data3[0].upper() == "INET":
                    datas.append("=================DELETE INTERNET=================")
                    log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action="Delete Internet", time=datetime.now(), command=f'{cmd_ont};{data2}', status='In Progress', message='No Error', logapp=logApp)
                    log.save()

                    if data_ip_port[4].upper() == "FH" or data_ip_port[4].upper() == "fh":
                        cmd = f'SET-WANSERVICE::{cmd_ip[0]}:5::STATUS=2,MODE=2,CONNTYPE=2,VLAN={data3[1]},COS=0,NAT=1,IPMODE=3,PPPOEPROXY=1,PPPOEUSER=aaa@aaa,PPPOEPASSWD=aaa,PPPOENAME=aaa,PPPOEMODE=1,UPORT=1;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'SET-WANSERVICE::{cmd_ip[0]}:5::STATUS=2,MODE=2,CONNTYPE=2,VLAN={data3[1]},COS=0,NAT=1,IPMODE=3,PPPOEPROXY=1,PPPOEUSER=aaa@aaa,PPPOEPASSWD=aaa,PPPOENAME=aaa,PPPOEMODE=1,UPORT=2;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'SET-WANSERVICE::{cmd_ip[0]}:5::STATUS=2,MODE=2,CONNTYPE=2,VLAN={data3[1]},COS=0,NAT=1,IPMODE=3,PPPOEPROXY=1,PPPOEUSER=aaa@aaa,PPPOEPASSWD=aaa,PPPOENAME=aaa,PPPOEMODE=1,UPORT=3;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'SET-WANSERVICE::{cmd_ip[0]}:5::STATUS=2,MODE=2,CONNTYPE=2,VLAN={data3[1]},COS=0,NAT=1,IPMODE=3,PPPOEPROXY=1,PPPOEUSER=aaa@aaa,PPPOEPASSWD=aaa,PPPOENAME=aaa,PPPOEMODE=1,UPORT=4;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'SET-WANSERVICE::{cmd_ip[0]}:5::STATUS=2,MODE=2,CONNTYPE=2,VLAN={data3[1]},COS=0,NAT=1,IPMODE=3,PPPOEPROXY=1,PPPOEUSER=aaa@aaa,PPPOEPASSWD=aaa,PPPOENAME=aaa,PPPOEMODE=1,SSID=1;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                    else:
                        cmd = f'DLT-ONUWAN::{cmd_ip[1]}:::WANID=1,IPHOSTID=1;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'DLT-ONUWANIP::{cmd_ip[1]}:::IPHOSTID=1;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'DEL-PONVLAN::{cmd_ip[0]}:5::CVLAN={data3[1]},UV={data3[1]},SERVICENAME=SPEEDY;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                if data3[0].upper() == "VOICE":
                    datas.append("=================DELETE VOICE=================")
                    log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action="Delete VOICE", time=datetime.now(), command=f'{cmd_ont};{data2}', status='In Progress', message='No Error', logapp=logApp)
                    log.save()

                    if data_ip_port[4].upper() == "FH" or data_ip_port[4].upper() == "fh":
                        cmd = f'DEL-VOIPSERVICE::{cmd_ip[0]},ONUPORT=1-1-1-1:5::;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                    else:
                        cmd = f'DEL-VOIPSERVICE::{cmd_ip[0]},ONUPORT=1-1-1-1:::;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'DEL-PONVLAN::{cmd_ip[0]}:5::CVLAN={data3[1]},UV={data3[1]},SERVICENAME=VOICE;\n'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                if data3[0].upper() == "IPTV":
                    datas.append("=================DELETE USEETV=================")
                    log = LogTL1(target=f"IP GPON: {ip_gpon}, SLOT/PORT: {slot}/{port}, SN: {sn}", action="Delete IPTV", time=datetime.now(), command=f'{cmd_ont};{data2}', status='Progress', message='No Error', logapp=logApp)
                    log.save()

                    if data_ip_port[4].upper() == "FH" or data_ip_port[4].upper() == "fh":
                        cmd = f'DEL-LANIPTVPORT::{cmd_ip[0]},ONUPORT=1-1-1-4:5::MVLAN=110;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'DEL-LANPORTVLAN::{cmd_ip[0]},ONUPORT=1-1-1-4:5::UV=111;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                    else:
                        cmd = f'CFG-LANPORT::{cmd_ip[0]},ONUPORT=1-1-1-4:::VLANMOD=None;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'CHG-ONUUNI-PON::{cmd_ip[1]},ONUPORT=4:::IPRETRIEVEMODE=NoControl;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'DEL-LANIPTVPORT::{cmd_ip[0]},ONUPORT=1-1-1-4:::MVLAN=110;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

                        cmd = f'DEL-PONVLAN::{cmd_ip[0]}:::CVLAN=111,UV=111,SERVICENAME=USEETV;'
                        tl1_cmd = tl1_command(s, cmd, datas, log, log.id)
                        if tl1_cmd['status'] == False:
                            logAppFailed(logApp.id)
                            
                            return JsonResponse(
                                {
                                    'status': tl1_cmd['status'],
                                    'data': tl1_cmd['data']
                                }
                            )

            if data_dump2[1].upper() == "FH":
                s.send(b'LOGOUT:::5::;')
                time.sleep(2)

            s.close()

        logAppSuccess(logApp.id)
        datas = '\n'.join(datas)
        request.session['hasil'] = datas
        request.session['hw'] = False
        return JsonResponse(
            {
                'status': True,
            }
        )

    else:
        vendor = ServerTl1.objects.values('vendor').order_by('vendor').annotate(vcount=Count('vendor'))

        placeholder = "Contoh Fiberhome :\n"
        placeholder += "=====DELETE ONT==========\n"
        placeholder += "ont|fh|172.29.215.6|6-6|FHTT06138248\n"
        placeholder += "=====DELETE INTERNET==========\n"
        placeholder += "other|fh|172.29.215.6|6-6|FHTT06138248;INET|1904\n"
        placeholder += "=====DELETE VOICE==========\n"
        placeholder += "other|fh|172.29.215.6|6-6|FHTT06138248;VOICE\n"
        placeholder += "=====DELETE IPTV==========\n"
        placeholder += "other|fh|172.29.215.6|6-6|FHTT06138248;IPTV\n"
        placeholder += "\n"
        placeholder += "\n"
        placeholder += "Contoh ZTE :\n"
        placeholder += "=====DELETE ONT==========\n"
        placeholder += "ont|zte|172.21.202.4|12-2|ZTEGC6753017\n"
        placeholder += "=====CREATE INTERNET==========\n"
        placeholder += "other|zte|172.21.202.4|12-2|ZTEGC6753017;INET|770\n"
        placeholder += "=====CREATE VOICE==========\n"
        placeholder += "other|zte|172.21.202.4|12-2|ZTEGC6753017;VOICE|571\n"
        placeholder += "=====CREATE IPTV==========\n"
        placeholder += "other|zte|172.21.202.4|12-2|ZTEGC6753017;IPTV\n"

        context = {
            'page_title': page_title,
            'vendors': vendor,
            'placeholder': placeholder,
            'client_ip': get_client_ip(request),
        }
        return render(request, 'config.html', context)

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
@user_passes_test(check_permissions)
def resultConfig(request):
    if request.is_ajax():
        if request.method == 'POST':
            if request.session.modified == False:
                del request.session['hasil']
                del request.session['hw']

            return JsonResponse(
                {
                    'status' : True
                }
            )

    if 'hasil' in request.session:
        hasil = request.session['hasil']
        hw = request.session['hw']
        vendor = ServerTl1.objects.values('vendor').order_by('vendor').annotate(vcount=Count('vendor'))

        context = {
            'page_title': 'Result',
            'vendors': vendor,
            'hasil' : hasil,
            'hw' : hw,
            'client_ip': get_client_ip(request),
        }

        if request.session.modified == False:
            del request.session['hasil']
            del request.session['hw']

        return render(request, 'result_config.html', context)

    else:

        return redirect('auto_tl1:home')

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
def daftar_perangkat(request, vendor_tipe):
    if session_login(request) == 'zero':
        return redirect('login:formOtp')

    if vendor_tipe == "zte":
        page_title = "Perangkat GPON ZTE"
        vendor_perangkat = "zte"

    elif vendor_tipe == "fh":
        page_title = "Perangkat GPON FIBERHOME"
        vendor_perangkat = "fh"

    else:
        page_title = "Perangkat GPON HUAWEI"
        vendor_perangkat = "hw"


    gpon = GponDevice.objects.select_related('ip_server').filter(ip_server__vendor=vendor_tipe).order_by('sto', 'hostname')
    vendor = ServerTl1.objects.values('vendor').order_by('vendor').annotate(vcount=Count('vendor'))
    context = {
        'page_title' : page_title,
        'gpons': gpon,
        'vendors': vendor,
        'vendor_perangkat' : vendor_perangkat,
        'client_ip': get_client_ip(request),
    }

    return render(request, 'perangkat.html', context)

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
def serverNms(request):
    if session_login(request) == 'zero':
        return redirect('login:formOtp')

    if request.method == 'POST':
        if request.is_ajax():
            server = ServerTl1.objects.get(ip_server=request.POST['ip_server'])
            param = '-n 3' if platform.system().lower() == 'windows' else '-c 3'
            restultado = os.popen(f'ping {param} {server.ip_server}').read()

            if request.is_ajax():
                if "TTL" in restultado:
                    server.status = 'up'
                    server.save()
                else:
                    server.status = 'down'
                    server.save()

            return JsonResponse({
                'status': server.status
            })

    else:
        vendor = ServerTl1.objects.values('vendor').order_by('vendor').annotate(vcount=Count('vendor'))
        server = ServerTl1.objects.values('id', 'name', 'ip_server', 'vendor', 'status', 'vendor')

        context = {
            'page_title' : 'Server NMS',
            'vendors' : vendor,
            'servers' : server,
            'client_ip': get_client_ip(request),
        }

        return render(request, 'servernms.html', context)

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
def cekLogApp(request):
    if session_login(request) == 'zero':
        return redirect('login:formOtp')

    vendor = ServerTl1.objects.values('vendor').order_by('vendor').annotate(vcount=Count('vendor'))
    dataLog = LogApp.objects.all().order_by('-time')
    context = {
        'page_title': 'Log SAC',
        'logapp' : dataLog,
        'vendors': vendor,
        'client_ip': get_client_ip(request),
    }

    return render(request, 'logapp.html', context)

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
def cekLog(request, logappId):
    if session_login(request) == 'zero':
        return redirect('login:formOtp')

    vendor = ServerTl1.objects.values('vendor').order_by('vendor').annotate(vcount=Count('vendor'))
    dataLog = LogTL1.objects.filter(logapp_id=logappId)
    context = {
        'page_title': 'Log',
        'logs' : dataLog,
        'vendors': vendor,
        'client_ip': get_client_ip(request),
    }

    return render(request, 'log.html', context)

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
def cekLogDetail(request, log_id):
    if session_login(request) == 'zero':
        return redirect('login:formOtp')

    vendor = ServerTl1.objects.values('vendor').order_by('vendor').annotate(vcount=Count('vendor'))
    dataLog = LogTL1.objects.filter(pk=log_id)

    context = {
        'page_title': 'Log',
        'logs': dataLog,
        'vendors': vendor,
        'client_ip': get_client_ip(request),
    }

    return render(request, 'logdetail.html', context)

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
def nossfLog(request):
    vendor = ServerTl1.objects.values('vendor').order_by('vendor').annotate(vcount=Count('vendor'))

    r = requests.get('http://cmon.telkom.co.id/cacti/noss-osm/cekorder.log')
    data = []
    data.append('')
    content = r.content.decode()
    if r.status_code == 200 and 'Mercusuar' not in content:
        data.append(content)
        data = '\n'.join(data)
        context = {
            'page_title': 'Log NOSS-F',
            'vendors': vendor,
            'client_ip': get_client_ip(request),
            'nossflog' : data
        }
    elif r.status_code == 500:
        context = {
            'page_title': 'Log NOSS-F',
            'vendors': vendor,
            'client_ip': get_client_ip(request),
            'nossflog': 'empty'
        }
    else:
        context = {
            'page_title': 'Log NOSS-F',
            'vendors': vendor,
            'client_ip': get_client_ip(request),
            'nossflog': 'empty'
        }

    return render(request, 'nossflog.html', context)

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
@user_passes_test(check_permissions)
def userActive(request):
    if session_login(request) == 'zero':
        return redirect('login:formOtp')

    vendor = ServerTl1.objects.values('vendor').order_by('vendor').annotate(vcount=Count('vendor'))
    context = {
        'page_title' : 'User Active',
        'vendors': vendor,
        'client_ip': get_client_ip(request),
    }
    return render(request, 'user_active.html', context)

@user_passes_test(check_permissions)
def tbUserActive(request, sessionid):
    if session_login(request) == 'zero':
        return redirect('login:formOtp')

    if sessionid == request.COOKIES['sessionid']:
        userActive = UserActive.objects.all().order_by('-last_login')
        context = {
            'userActives' : userActive,
        }
        return render(request, 'tb_user_active.html', context)

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
def getPdf(request, vendor_tipe):
    if session_login(request) == 'zero':
        return redirect('login:formOtp')

    if vendor_tipe == "zte":
        page_title = "Perangkat GPON ZTE"

    elif vendor_tipe == "fh":
        page_title = "Perangkat GPON FIBERHOME"

    else:
        page_title = "Perangkat GPON HUAWEI"

    gpon = GponDevice.objects.select_related('ip_server').filter(ip_server__vendor=vendor_tipe).order_by('sto', 'hostname')

    context = {
        'page_title': page_title,
        'gpons': gpon,
        'date' : datetime.now(),
        'client_ip': get_client_ip(request),
    }
    pdf = render_to_pdf('cetak_perangkat.html', context)
    return HttpResponse(pdf, content_type='application/pdf')

@login_required(login_url=settings.URL_SEBELUM_LOGIN)
def getExcel(request, vendor_tipe):
    if session_login(request) == 'zero':
        return redirect('login:formOtp')

    response = HttpResponse(content_type='application/ms-excel')
    response['Content-Disposition'] = 'attachment; filename="Gpon.xls"'

    wb = xlwt.Workbook(encoding='utf-8')
    ws = wb.add_sheet('GPON')

    # Sheet header, first row
    row_num = 0

    font_style = xlwt.XFStyle()
    font_style.font.bold = True

    columns = ['HOSTNAME', 'IP GPON', 'VLAN INTERNET', 'VLAN VOICE', 'STO', 'SERVER', ]

    for col_num in range(len(columns)):
        ws.write(row_num, col_num, columns[col_num], font_style)

    # Sheet body, remaining rows
    font_style = xlwt.XFStyle()

    rows = GponDevice.objects.select_related('ip_server').filter(ip_server__vendor=vendor_tipe).values_list('hostname', 'ip_gpon', 'vlan_inet', 'vlan_voice', 'sto__sto_name', 'ip_server__name', )
    for row in rows:
        row_num += 1
        for col_num in range(len(row)):
            ws.write(row_num, col_num, row[col_num], font_style)

    wb.save(response)
    return response

class GponApi(APIView):

    def get(self, request):
        gpon = GponDevice.objects.all()
        serializer = GponSerializer(gpon, many=True)
        return Response({'gpon' : serializer.data})

    def post(self, request):
        gpon = GponDevice.objects.all()
        serializer = GponSerializer(data=gpon)
        if serializer.is_valid(raise_exception=True):
            gpon_saved = serializer.save()
        return Response({'success' : f"Gpon {gpon_saved.hostname} create successfully"})

@api_view(['GET'])
def gpon_all_api(request):
    gpon = GponDevice.objects.all()
    serializer = GponSerializer(gpon, many=True)
    return JsonResponse({"data_gpon" : serializer.data})

@api_view(['GET'])
def gpon_get_api(request, name_gpon):
    gpon = GponDevice.objects.filter(sto__sto_code=name_gpon)
    serializer = GponSerializer(gpon, many=True)
    datas = serializer.data

    return JsonResponse(datas, safe=False)

@api_view(['POST'])
def login_api(request):
    username_login = request.POST['username']
    password_login = request.POST['password']

    user = authenticate(request, username=username_login, password=password_login)

    data = {'status' : 'failed'}

    if user is not None:
        data['status'] = "success"
        user_data = User.objects.get(username=username_login)
        data['user'] = user_data.username
        if user_data.is_staff:
            data['level'] = 'admin'
        else:
            data['level'] = 'superadmin'

    return JsonResponse(data)