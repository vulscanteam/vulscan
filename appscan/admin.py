#coding=utf-8
from django.contrib import admin

# Register your models here.

from appscan.models import poc_list
from appscan.models import navigation,navigation_url,vul_scan, user_scan,vul_state

#POC 数据
class poc_listAdmin(admin.ModelAdmin):
    list_display = ('vulID','category','vulType','cvss','filename','appName','appPowerLink','appVersion','author','createDate','desc','install_requires','name','references','samples','updateDate','version',) # 列表显示的字段
admin.site.register(poc_list,poc_listAdmin)

#导航菜单
class navigationAdmin(admin.ModelAdmin):
    list_display = ('id','nav_name',) # 列表显示的字段  
admin.site.register(navigation,navigationAdmin)
#导航数据
class navigation_urlAdmin(admin.ModelAdmin):
    list_display = ('id','nav_name','nav_title','nav_url',) # 列表显示的字段
admin.site.register(navigation_url,navigation_urlAdmin)

#漏洞扫描
class vul_scanAdmin(admin.ModelAdmin):
    list_display = ('id','username','appname','url', 'pocname', 'date', 'cvss') # 列表显示的字段
admin.site.register(vul_scan,vul_scanAdmin)

#用户扫描
class user_scanAdmin(admin.ModelAdmin):
    list_display = ('id', 'username', 'url', 'date')
admin.site.register(user_scan,user_scanAdmin)

#漏洞修复
class vul_stateAdmin(admin.ModelAdmin):
    list_display = ('id', 'url', 'vulname','cvss','state')
admin.site.register(vul_state, vul_stateAdmin)


