# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render
from django.db.models import Count

from appscan.models import vul_scan
from appscan.models import user_scan
import datetime, time

# Create your views here.
def get_db_info(request):
	response = {}

	end_time = datetime.datetime.now().date()
	week_begin_time = end_time -datetime.timedelta(days=7)
	

	week_vuls = vul_scan.objects.filter(date__gte=week_begin_time).filter(date__lte=end_time).count()
	week_scan = user_scan.objects.filter(date__gte=week_begin_time).filter(date__lte=end_time).count()
	week_cvss_yanzhong = vul_scan.objects.filter(date__gte=week_begin_time).filter(date__lte=end_time).filter(cvss=u'严重').count()
	week_cvss_gaowei = vul_scan.objects.filter(date__gte=week_begin_time).filter(date__lte=end_time).filter(cvss=u'高危').count()
	week_cvss_zhongwei = vul_scan.objects.filter(date__gte=week_begin_time).filter(date__lte=end_time).filter(cvss=u'中危').count()
	week_cvss_diwei = vul_scan.objects.filter(date__gte=week_begin_time).filter(date__lte=end_time).filter(cvss=u'低危').count()
	
	
	
	paiming = vul_scan.objects.values('pocname').annotate(num_poc=Count('pocname')).order_by('num_poc')

	for v in paiming:
		print v
	
		
	#输出
	response['week_scan'] = week_scan #周扫描数

	response['week_vuls'] = week_vuls #周漏洞数

	response['week_cvss_yanzhong'] = week_cvss_yanzhong
	response['week_cvss_gaowei'] = week_cvss_gaowei
	response['week_cvss_zhongwei'] = week_cvss_zhongwei
	response['week_cvss_diwei'] = week_cvss_diwei

	response['paiming'] = paiming
	return render(request, 'baobiao_weekly.html', response)