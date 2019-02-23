#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2014-2015 pocsuite developers (http://seebug.org)
See the file 'docs/COPYING' for copying permission
"""
#命令行
from pocsuite import pocsuite_cli
#验证模块
from pocsuite import pocsuite_verify
#攻击模块
from pocsuite import pocsuite_attack
#控制台模式
from pocsuite import pocsuite_console
from pocsuite.api.request import req 
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase


class FckeditorPOC(POCBase):
    vulID = '6'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2017-03-13' #漏洞公开的时间,不知道就写今天

    author = 'ly55521' #  PoC作者的大名
    createDate = '2017-03-13'# 编写 PoC 的日期
    updateDate = '2017-03-13'# PoC 更新的时间,默认和编写时间一样
    references = 'http://0535code.com/'# 漏洞地址来源,0day不用写
    name = 'Fckeditor info'# PoC 名称
    appPowerLink = 'http://ckeditor.com/'# 漏洞厂商主页地址
    appName = 'Fckeditor'# 漏洞应用名称
    appVersion = 'unknown'# 漏洞影响版本
    vulType = 'file-upload'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        Fckeditor上传解析漏洞 
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危" #严重,高危,中危,低危
    #定义字典常量
    fckdir = [
        "FCKeditor2.3/",
        "server/fckeditor/editor/fckdebug.html",
        "mambots/editors/fckeditor",
        "FCKeditor2/",
        "admin/fckeditor/editor/filemanager/upload/php/upload.php",
        "FCKeditor/editor/dialog/",
        "admin/fckeditor/editor/filemanager/upload/asp/upload.asp",
        "includes/fckeditor/editor/filemanager/upload/asp/upload.asp",
        "includes/fckeditor/editor/filemanager/upload/php/upload.php",
        "FCKeditor21/",
        "includes/fckeditor/editor/filemanager/connectors/aspx/connector.aspx",
        "manage/fckeditor",
        "FCKeditor2.2/",
        "fckeditor/editor/filemanager/browser/default/connectors/php/connector.php",
        "manage/fckeditor",
        "admin/fckeditor/editor/filemanager/connectors/aspx/upload.aspx",
        "admin/fckeditor/editor/filemanager/connectors/asp/connector.asp",
        "html/editor/fckeditor/editor/filemanager",
        "fckeditor/editor/filemanager/connectors/asp/connector.asp",
        "fckeditor/editor/filemanager/browser/default/connectors/asp/connector.asp",
        "includes/fckeditor/editor/filemanager/connectors/asp/upload.asp",
        "assets/fckeditor",
        "fckeditor/editor/filemanager/upload/aspx/upload.aspx",
        "web/FCKeditor/editor/filemanage",
        "inc/fckeditor/",
        "fckeditor/editor/filemanager/connectors/asp/upload.asp",
        "admin/FCKeditor/editor/filemanage",
        "browser/trunk/fckeditor/editor/filemanager/",
        "FCKeditor22/",
        "scripts/fckeditor/editor/filemanager/",
        "admin/fckeditor/editor/filemanager/connectors/asp/upload.asp",
        "inc/fckeditor",
        "includes/fckeditor/editor/filemanager/connectors/php/connector.php",
        "system/Fckeditor",
        "admin/FCKeditor",
        "editors/FCKeditor",
        "fckeditor",
        "javascript/editors/fckeditor",
        "include/fckeditor",
        "FCKeditor/editor/filemanager/browser/default/connectors/php/connector.php",
        "boke/Edit_Plus/FCKeditor/editor/",
        "js/editor/fckeditor/editor/filemanager",
        "FCKeditor23/",
        "plugins/fckeditor",
        "includes/fckeditor/editor/filemanager/browser/default/connectors/aspx/connector.aspx",
        "resources/fckeditor",
        "tools/fckeditor/editor/filemanager",
        "FCKeditor20/",
        "includes/fckeditor/editor/filemanager",
        "html/js/editor/fckeditor/editor/filemanager",
        "fckeditor/editor/filemanager/connectors/aspx/upload.aspx",
        "FCKeditor2.4/",
        "admin/fckeditor",
        "machblog/browser/trunk/fckeditor/editor/filemanager/",
        "fckeditor/editor/filemanager/connectors/aspx/connector.aspx",
        "FCKeditor",
        "admin/fckeditor/editor/filemanager/upload/aspx/upload.aspx",
        "admin/fckeditor/editor/filemanager/browser/default/connectors/asp/connector.asp",
        "results/fckeditor/editor/filemanage",
        "editor/FCKeditor/editor/filemanager",
        "fckEditor/editor/",
        "editor/FCKeditor",
        "ocomon/includes/fckeditor/editor/filemanager",
        "sites/all/modules/fckeditor",
        "FCKeditor24/",
        "fckeditor/editor/filemanager/upload/asp/upload.asp",
        "demo/fckeditor/editor/filemanager",
        "web_Fckeditor",
        "sites/all/libraries/fckeditor",
        "includes/fckeditor/editor/filemanager/connectors/php/upload.php",
        "FCKeditor/editor/filemanage",
        "apps/trac/pragyan/browser/trunk/cms/modules/article/fckEditor/editor/filemanage",
        "gs/plugins/editors/fckeditor",
        "include/fckeditor/",
        "adm/fckeditor",
        "thirdparty/fckeditor",
        "includes/fckeditor/editor/filemanager/connectors/aspx/upload.aspx",
        "admin/fckeditor/editor/filemanager/connectors/aspx/connector.aspx",
        "common/FckEditor/editor/filemanager",
        "includes/fckeditor/editor/filemanager/connectors/asp/connector.asp",
        "fckeditor/editor/filemanager/connectors/php/connector.php",
        "lib/fckeditor",
        "blog/fckeditor",
        "CFIDE/scripts/ajax/FCKeditor",
        "ispcp/browser/trunk/gui/tools/filemanager/plugins/fckeditor/editor/filemanager",
        "demo/admin/fckeditor/editor/filemanager",
        "admin/fckeditor/editor/filemanager/connectors/php/upload.php",
        "fckeditor/editor/filemanager/browser/default/connectors/aspx/connector.aspx",
        "includes/fckeditor/editor/filemanager/upload/aspx/upload.aspx",
        "assets/js/fckeditor",
        "fckeditor/editor/filemanager/upload/php/upload.php",
        "FCKeditor2.1/",
        "js/FCKeditor",
        "admin/scripts/fckeditor",
        "admin/fckeditor/editor/filemanager/browser/default/connectors/php/connector.php",
        "FCKeditor/",
        "fckeditor/editor/filemanager/connectors/php/upload.php",
        "INC/FckEditor/editor/filemanager",
        "fck",
        "includes/fckeditor/editor/filemanager/browser/default/connectors/php/connector.php",
        "lib/fckeditor/",
        "common/INC/FckEditor/editor/filemanager",
        "plugins/editors/fckeditor",
        "includes/fckeditor",
        "admin/fckeditor/editor/filemanager/browser/default/connectors/aspx/connector.aspx",
        "includes/fckeditor/editor/filemanager/browser/default/connectors/asp/connector.asp",
        "admin/fckeditor/editor/filemanager/connectors/php/connector.php",
        "FCKeditor2.0/",
        "ThirdPartyControl/fckeditor/editor/filemanage",
    ]

    #验证漏洞 pocsuite -r 6-Fckeditor-info.py -u 127.0.0.1 --verify
    def _verify(self):
        #定义返回结果
        result = {}
        #获取漏洞url
        vul_url = '%s' % self.url
        from urlparse import urlparse, urlunparse, urljoin
        urlinfo = urlparse(vul_url)
        check_url = urlunparse((urlinfo.scheme, urlinfo.netloc, '/', '', '', ''))
        #print check_url
        
        payload_dict = {}
        final_url = []
        for fckurl in self.fckdir:
            targetURL = urljoin(check_url, fckurl) 
            #print targetURL
            try:
                r = req.get(url=targetURL, timeout=1,allow_redirects=False) #禁止重定向
                # print targetURL,r.status_code
                if r.status_code in [200,300,202]:

                    #print u"存在漏洞",targetURL
                    # payload_url.append(targetURL)
                    payload_dict[targetURL] = r.text
            except Exception,e:
                pass
                # print "error",e,targetURL
            #return result
        #print payload_url
        if len(payload_dict) > 0:
            for i in payload_dict:
                if payload_dict.values().count(payload_dict[i]) == 1:
                    final_url.append(i)
            if (len(final_url) != 0 and len(final_url) < 15 ) :
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vul_url
                result['VerifyInfo']['Payload'] = str(final_url)
            #print result
        print '[+]6 poc done'
        return self.save_output(result)

    #漏洞攻击
    def _attack(self):
        result = {}
        # 攻击代码
        return self._verify()

    def save_output(self, result):
        #判断有无结果并输出
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

register(FckeditorPOC)

