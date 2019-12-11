from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class UserTg(models.Model):
    auth_user = models.OneToOneField(User, models.DO_NOTHING, unique=True)
    id_chat = models.CharField(max_length=50)

    def __str__(self):
        return f'{self.auth_user.username} - {self.auth_user.first_name} {self.auth_user.last_name}'

class ServerTl1(models.Model):
    ip_server = models.CharField(max_length=25, unique=True)
    name = models.CharField(max_length=50)
    vendor_choices = (
        ('fh', 'FIBERHOME'),
        ('zte', 'ZTE'),
        ('hw', 'HUAWEI'),
    )
    vendor = models.CharField(max_length=10, choices=vendor_choices)
    status = models.CharField(max_length=10, default='down')
    port_tl1 = models.IntegerField(default=65535)
    user_tl1 = models.CharField(max_length=50, blank=True)
    pass_tl1 = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return self.name

class Sto(models.Model):
    sto_code = models.CharField(primary_key=True, max_length=10)
    sto_name = models.CharField(max_length=25)

    def __str__(self):
        return self.sto_name

class GponDevice(models.Model):
    ip_gpon = models.CharField(max_length=20, unique=True)
    hostname = models.CharField(max_length=50, unique=True)
    vlan_inet = models.IntegerField(default=1)
    vlan_voice = models.CharField(max_length=15, default='1')
    ip_server = models.ForeignKey(ServerTl1, related_name='server_gpon', on_delete=models.CASCADE)
    sto = models.ForeignKey(Sto, related_name='sto_gpon', on_delete=models.CASCADE)

    def __str__(self):
        return f'{self.hostname}({self.ip_gpon})'

class LogApp(models.Model):
    target = models.CharField(max_length=255)
    action = models.CharField(max_length=50)
    status = models.CharField(max_length=25)
    time = models.DateTimeField(null=True)
    stoptime = models.DateTimeField(null=True)
    ip_client = models.CharField(max_length=255)
    username = models.CharField(max_length=255)

    def __str__(self):
        return "{} - {} - {}".format(self.target, self.ip_client, self.username)

class LogTL1(models.Model):
    target = models.CharField(max_length=255)
    action = models.CharField(max_length=255)
    status = models.CharField(max_length=25)
    message = models.CharField(max_length=255)
    time = models.DateTimeField(null=True)
    stoptime = models.DateTimeField(null=True)
    command = models.CharField(max_length=255)
    logapp = models.ForeignKey(LogApp, related_name='logapp_tl1', on_delete=models.CASCADE)

    def __str__(self):
        return "{} - {}".format(self.action, self.target)

class CmdTL1(models.Model):
    command_tl1 = models.TextField()
    result_tl1 = models.TextField()
    logtl1 = models.ForeignKey(LogTL1, related_name='logtl1_cmd', on_delete=models.CASCADE)

    def __str__(self):
        return self.command_tl1

class UserActive(models.Model):
    sessionid = models.CharField(primary_key=True, max_length=255)
    username = models.CharField(max_length=255)
    last_login = models.DateTimeField(null=True)
    ip_client = models.CharField(max_length=255)
    level = models.CharField(max_length=255)

    def __str__(self):
        return self.username