from django.urls import path
from . import views

app_name = 'login'
urlpatterns = [
    path('login/', views.formLogin, name='formlogin'),
    path('login/choiceotp/', views.formPilihOTP, name='formOtp'),
    path('login/choiceotp/<str:tipe>', views.pilihOTP, name='pilihOtp'),
    path('login/gettoken/', views.getToken, name='getToken'),
    path('login/formtoken/', views.formToken, name='formtoken'),
    path('login/cektoken/', views.cekToken, name='cektoken'),
    path('login/proses_login/', views.loginView, name='proses_login'),
    path('logout/', views.logoutView, name='proses_logout'),
    path('session/flush/', views.flushSession, name='flush'),
]