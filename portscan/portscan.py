#coding=utf-8
import nmap
import json

#win下需要安装 nmap库外 还需要安装 nmap.exe 并配置环境变量 http://www.nmap.com.cn/; C:\Program Files (x86)\Nmap\ 配置环境变量后需重启
class Port(object):
    """docstring for Port"""
    def __init__(self, ip):
        self.state = 'unscan' #未扫描
        self.ip = ip
        self.report = ''

    def port_scan(self,):
        host = self.ip
        nm = nmap.PortScanner()
        self.state = 'scanning'
        try:
            nm.scan(host) #arguments='-T5 -p 1-65535 -sV -sT -Pn --host-timeout 3600'
            ports = nm[host]['tcp'].keys()
            report_list = []
            for port in ports:
                report = {}
                state = nm[host]['tcp'][port]['state']
                service = nm[host]['tcp'][port]['name']
                product = nm[host]['tcp'][port]['product']
                report['port'] = port
                report['state'] = state
                report['service'] = service
                report['product'] = product
                if state == 'open':
                    report_list.append(report)
            print report_list
            self.state = 'scanned'
            self.report = json.dumps(report_list)
            return json.dumps(report_list)
        except Exception as e:
            print e
