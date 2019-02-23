
# VulScan [![License](https://img.shields.io/aur/license/yaourt.svg)](https://github.com/vulscanteam/vulscan/blob/master/LICENSE)
----------

**VulScan**是一款基于Pocsuite开发的POC插件扫描器，遵循高内聚、低耦合、轻量级 vulscan poc管理工具，使用django
做web界面友好的集成了Pocsuite-dev、支持扩展模块、扩展POC等功能！

**请使用者遵守 [中华人民共和国网络安全法] （http://www.npc.gov.cn/npc/xinwen/2016-11/07/content_2001605.htm）"， 勿将VulScan用于非授权的测试，Vulscan开发者不负任何连带法律责任。**

主要功能：`一键扫描` `POC插件` `端口扫描` `基线检查` `网址导航` `扩展模块` 等等;

**一键扫描**

![](https://github.com/vulscanteam/vulscan/blob/master/webscan/demo/1.png)

**POC插件**

![](https://github.com/vulscanteam/vulscan/blob/master/webscan/demo/2.png)

**端口扫描**

![](https://github.com/vulscanteam/vulscan/blob/master/webscan/demo/3.png)

**基线检查**

![](https://github.com/vulscanteam/vulscan/blob/master/webscan/demo/4.png)

**网址导航**

![](https://github.com/vulscanteam/vulscan/blob/master/webscan/demo/5.png)

**扩展模块**

![](https://github.com/vulscanteam/vulscan/blob/master/webscan/demo/5.png)


## 安装指南 [![Python 2.7](https://img.shields.io/badge/python-2.7-yellow.svg)](https://www.python.org/) 

**安装命令：pip install -r requirements.txt**

（打包命令：pip freeze> requirements.txt //如果开发POC需要新的依赖库，在这里记录，尽可能的不使用依赖库减少依赖）
（默认账户demo，密码demo123456）

## 插件编写
**目录下的Template.py为插件模版，基于pocsuite配置了一些规则**

## 目录结构

- accounts 				#账户应用
- appscan 				#扫描应用
- jixianjiancha 	#基线检查应用
- log 					  #日志路径
- plug 					  #扩展应用
- pocsuite 				#pocsuite核心库
- portscan 				#端口扫描应用
- vul 					  #POC存放目录
- weakpass				#弱口令文件
- webscan				  #主项目


## 维护作者
- ly55521
- colorway
- xiaohuihui1
- arr0w1

## 问题反馈

**微信群二维码：（如果二维码过期，加微信 baidunew 入群）**

![](https://github.com/vulscanteam/vulscan/blob/master/webscan/demo/0.png)


