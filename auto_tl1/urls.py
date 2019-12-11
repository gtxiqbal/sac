from django.urls import path
from auto_tl1 import views
from auto_tl1.views import GponApi
from login_app import views as view_login
from rest_framework.urlpatterns import format_suffix_patterns


app_name = 'auto_tl1'
urlpatterns = [
    path('', views.index, name='home'),
    path('cek/<str:cek_tipe>/<str:vendor_code>/', views.cekSN, name='ceksn'),
    path('ceksnunreg/<str:vendor_code>/', views.cekUnregSN, name='ceksnunreg'),
    path('ceksnreg/<str:vendor_code>/', views.cekRegSN, name='ceksnreg'),
    path('ceksnstat/<str:vendor_code>/', views.cekStatusSN, name='ceksnstat'),
    path('cekservice/<str:vendor_code>/', views.cekservice, name='cekservice'),
    path('wifiservice/<str:vendor_code>/', views.wifiService, name='wifi'),
    path('ceksto/', views.cekSto, name='ceksto'),
    path('config_gui/<str:vendor_code>/', views.config_gui, name='config_gui'),
    path('config/<str:vendor_code>/', views.config, name='config'),
    path('configbatch/', views.config_batch, name='config_batch'),
    path('deletebatch/', views.delete_config_batch, name='delete_config_batch'),
    path('verify_config/result/', views.resultConfig, name='result_config'),
    path('sop/<str:sop_tipe>/', views.sop, name='sop_batch'),
    path('cetak_pdf/<str:vendor_tipe>/', views.getPdf, name='cetakpdf'),
    path('export_excel/<str:vendor_tipe>/', views.getExcel, name='cetakexcel'),
    path('perangkat/<str:vendor_tipe>/', views.daftar_perangkat, name='perangkat'),
    path('status/nms/', views.serverNms, name='nms'),
    path('status/nossflog/', views.nossfLog, name='nossflog'),
    path('monitor/log/', views.cekLogApp, name='logapp'),
    path('monitor/log/tl1/<int:logappId>', views.cekLog, name='logtl1'),
    path('monitor/log/tl1/detail/<int:log_id>', views.cekLogDetail, name='logdetail'),
    path('monitor/tbuseractive/<str:sessionid>/', views.tbUserActive, name='tbuseractive'),
    path('monitor/useractive/', views.userActive, name='useractive'),
    path('monitor/useractive/terminate/', view_login.terminate, name='terminate'),
    path('login_api/', views.login_api, name='login_api'),
    path('gpon_all/', views.gpon_all_api, name='api_gpon'),
    path('gpon_get/<str:name_gpon>/', views.gpon_get_api, name='api_gpon_get')
]