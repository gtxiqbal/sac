from django.contrib import admin
from .models import LogTL1, GponDevice, ServerTl1, UserActive, Sto, UserTg, CmdTL1, LogApp

admin.site.register(ServerTl1)

admin.site.register(UserTg)

class CmdTL1TabLine(admin.TabularInline):
    model = CmdTL1

class LogTL1Admin(admin.ModelAdmin):
    list_display = ('action', 'target', 'time', 'command')
    list_display_links = ('action',)
    search_fields = ('target', 'command')
    list_per_page = 25
    ordering = ('-time',)
    inlines = [
        CmdTL1TabLine,
    ]
admin.site.register(LogTL1, LogTL1Admin)

class LogTlTabLine(admin.TabularInline):
    model = LogTL1

class LogAppAdmin(admin.ModelAdmin):
    list_display = ('action', 'status', 'time', 'stoptime', 'ip_client', 'username')
    list_per_page = 25
    ordering = ('-stoptime',)
    inlines = [
        LogTlTabLine,
    ]
admin.site.register(LogApp, LogAppAdmin)

class GponDeviceTabLine(admin.TabularInline):
    model = GponDevice

class StoAdmin(admin.ModelAdmin):
    list_display = ('sto_code', 'sto_name')
    search_fields = ('sto_code', 'sto_name')
    list_per_page = 10
    ordering = ('sto_code',)
    inlines = [
        GponDeviceTabLine,
    ]
admin.site.register(Sto, StoAdmin)

class GponDeviceAdmin(admin.ModelAdmin):
    list_display = ('hostname', 'ip_gpon', 'vlan_inet', 'vlan_voice', 'sto', 'ip_server')
    list_display_links = ('hostname', 'ip_gpon')
    list_filter = ('sto', 'ip_server')
    search_fields = ('hostname', 'ip_gpon', 'sto__sto_name')
    list_per_page = 10
    ordering = ('sto', 'hostname')
admin.site.register(GponDevice, GponDeviceAdmin)

admin.site.register(UserActive)
admin.site.site_header = "GTX WOC"
admin.site.site_title = "GTX WOC"
admin.site.index_title = "Administration"