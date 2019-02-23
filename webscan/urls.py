#coding=utf-8
"""webscan URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.10/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url,include
from django.contrib import admin
#appscan
from appscan import views as appscan_views
from appscan import scan_views
from appscan import navigation_views
from appscan import api_views
from appscan import history_view
#
from portscan import views as port_views
from jixianjiancha import views as jixian_views
from jixianjiancha import baobiao as jixian_baobiao
#accounts
from accounts import views as accounts_views
#plug
from plug import views as plug_views #
from plug import lan_views #C段扫描
from plug import weakpass_views #弱口令扫描
from plug import weekly_views #一键扫描周报
from plug import monthly_views #一键扫描月报
from plug import tooler_views #编码工具
from plug import spider_views #百度爬虫
from plug import zoomeye_views #钟馗之眼接口
from plug import fingerprint_views #指纹识别接口

urlpatterns = [
    #后台及登陆配置
    url(r'^admin/', admin.site.urls),
    url(r'^logout/$', accounts_views.logout,name="logout"),
    url(r'^login/$',accounts_views.login,name="login"),
    #程序版本校验 升级
    url(r'^update/$',appscan_views.update,name="update"),#更新poc操作,返回需要更新的poc json
    url(r'^poc_list_json/$',appscan_views.poc_list_json,name="poc_list_json"),#请求poc_list返回json
    url(r'^version/$',appscan_views.version,name="version"),#请求程序版本号
    url(r'^main_version/$',appscan_views.main_version,name="main_version"),#返回程序更新标识
    #一键扫描
    url(r'^$',appscan_views.index,name="index"), #首页
    url(r'^vulscan$',appscan_views.vulscan,name="vulscan"), #检测扫描
    url(r'^vulscan/json$',appscan_views.vulscan_json,name="vulscan_json"), #ajax 实时返回扫描结果
    url(r'^vulscan/jindu$',appscan_views.vulscan_jindu,name="vulscan_jindu"), #ajax 实时返回扫描进度
    url(r'^vulscan/report$',appscan_views.vulscan_report,name="vulscan_report"), #ajax 返回扫描结果
    #漏洞分析
    url(r'^analysis/$', appscan_views.analysis, name="analysis"),#漏洞分析 首页
    #学习导航
    url(r'^navigation/$',navigation_views.index,name="navigation"),#导航首页
    #程序说明
    url(r'^help/$',appscan_views.help,name="help"),#版本说明
    #Open api
    url(r'^api$',api_views.index,name="api"),#api    
    #POC插件
    url(r'^scan/$',scan_views.index,name="scan"),#POC插件 首页
    url(r'^scan/vulid/(\d+)$',scan_views.vulid,name="vul_scan"),#POC扫描页面
    url(r'^scan/poc_scan/$',scan_views.poc_scan,name="poc_scan"),#POC扫描接口
    url(r'^scan/vulid_report/$',scan_views.vulid_report,name="vulid_report"),#返回扫描json报告
    #端口扫描
    url(r'^portscan/$', port_views.index, name="port"),
    url(r'^portscan/check/$', port_views.port_scan, name="port_check"),#端口扫描
    url(r'^portscan/jindu$',port_views.get_port_scan_state,name="port_jindu"),#扫描进度
    url(r'^portscan/report$',port_views.get_port_scan_report,name="port_report"),#扫描报告
    #linux系统基线检查
    url(r'^jixianjiancha/$', jixian_views.index, name="jixian"),
    url(r'^jixianjiancha/check/$', jixian_views.check, name="jixian_check"),
    url(r'^jixianjiancha/executeScript/$', jixian_views.execute, name="jixian_execute"),
    url(r'^jixianjiancha/deleteScript/$', jixian_views.delete, name="jixian_delete"),
    #报表-基线检查
    url(r'^jixianjiancha/baobiao_week/$', jixian_baobiao.week, name="jixian_weekly"),
    url(r'^jixianjiancha/baobiao_month/$', jixian_baobiao.month, name="jixian_monthly"),

    #插件模块
    url(r'^plug$',plug_views.index,name="plug"),#plug
    #C段扫描
    url(r'^plug/lan/$',lan_views.index,name="lan"),#C段 首页
    url(r'^plug/lan_scan/$',lan_views.lan_scan,name="lan_scan"),#C段 扫描任务处理
    url(r'^plug/lan_json/$',lan_views.lan_json,name="lan_json"),#C段 异步返回
    url(r'^plug/scan_jindu/$',lan_views.scan_jindu,name="scan_jindu"),#返回扫描进度 
    url(r'^plug/scan_report/$',lan_views.scan_report,name="scan_report"),#返回扫描json报告
    #弱口令扫描
    url(r'^plug/weakpass/$',weakpass_views.index,name="weakpass"),#弱口令首页 
    url(r'^plug/weakpass_jindu/$',weakpass_views.weakpass_jindu,name="weakpass_jindu"),#弱口令扫描进度  
    url(r'^plug/weakpass_json/$',weakpass_views.weakpass_json,name="weakpass_json"), #r弱口令扫描结果 
    url(r'^plug/weakpass_run/$',weakpass_views.weakpass_run,name="weakpass_run"),#弱口令表单处理
    #报表-漏扫扫描
    url(r'^plug/baobiao_weekly/$', weekly_views.get_db_info, name="baobiao_weekly"), 
    url(r'^plug/baobiao_monthly/$',monthly_views.get_db_info, name="baobiao_monthly"),
    #编码工具
    url(r'^plug/tooler/$',tooler_views.index,name = 'tooler'),
    #爬虫
    url(r'^plug/spider/$',spider_views.index,name="plug_spider"), #爬虫首页
    url(r'^plug/spider/spider/$',spider_views.spider_action,name="plug_ajax_spider"), # ajax 爬虫处理
    url(r'^plug/spider/get_jindu/$',spider_views.get_jindu,name="plug_ajax_get_jindu"), # ajax 爬虫任务进度
    url(r'^plug/spider/show_tables/results',spider_views.show_tables,name="plug_show_tables"), # 下载显示结果为txt
    url(r'^plug/spider/delete_tables$',spider_views.delete_tables,name="plug_delete_tables"), # 删除结果数据
    url(r'^plug/spider/delete_url/(\d+)$',spider_views.delete_url,name="plug_delete_url"), # 删除一条数据
    #钟馗之眼接口
    url(r'^plug/zoomeye/$',zoomeye_views.index,name="plug_zoomeye"),#钟馗之眼首页
    url(r'^plug/zoomeye/delete_tables_host$',zoomeye_views.delete_tables_host,name="plug_delete_tables_host"), # 删除HOST结果数据
    url(r'^plug/zoomeye/delete_tables_web$',zoomeye_views.delete_tables_web,name="plug_delete_tables_web"), # 删除WEB结果数据    
    #指纹识别
    url(r'^plug/fingerprint$',fingerprint_views.index,name="plug_fingerprint"),#指纹识别首页
    #用户漏洞状态、历史漏洞管理
    url(r'^history/$', history_view.index, name="history_views"),  # 历史漏洞
    # url(r'^history/show$', history_view.show, name="history_show"),  # 历史漏洞展示
    url(r'^history/ignore$', history_view.ignore, name="vul_ignore"),  # 漏洞忽略
    url(r'^history/rescan$', history_view.rescan_all, name="vuls_rescan"),  # 漏洞一键检测修复

    #url(r'^vul_details/$', vul_views.test, name="vul_details"),
]