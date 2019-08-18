# -*-coding: utf8 -*-

#import dns.resolver
import os
import subprocess
import socket
import whois
import json
import urllib.request
from urllib.request import urlopen
import time
import requests

from django.http import HttpResponse

### 转换为时间戳
def unix_time(dt):
    # 转换成时间数组
    timeArray = time.strptime(dt, "%Y-%m-%d %H:%M:%S")
    # 转换成时间戳
    timestamp = int(time.mktime(timeArray))
    return timestamp


### query domain information : whois sakaqi.com
def get_domain_information(request):
    if request.method == "POST":
        py_body = json.loads(request.body.decode('utf-8'))
        domain = py_body["domain_name"]
        information = json.loads(str(whois.whois(domain)))
        response = {'name_servers':information['name_servers'],'status':information['status'],'expiration_date':information['expiration_date'],'dnssec':information['dnssec'],'registrar':information['registrar']}
        return HttpResponse(json.dumps(response))
    else:
        return HttpResponse("error")


### get ip Attribution: DB
def get_ip_attribution(request):
    if request.method == "POST":
        py_body = json.loads(request.body.decode('utf-8'))
        client_ip = py_body["ip"]
        client_c = subprocess.getoutput("echo" + " " + client_ip + "| awk -F \".\" '{print $1\".\"$2\".\"$3}'")
        prov_name = subprocess.getoutput("mysql -h10.249.50.199 -P16764 -uroot -p'vXi3m^YM93' --default-character-set=utf8 -A -e" + " " + "\"select prov_name from dnspod_ip_location.Province_Code where prov_id=(select bProvince from dnspod_ip_location.Tbl_IP_Province_ISP where strIP = " + client_c + ".0" + ")\"")
        return HttpResponse(prov_name)
    else:
        return HttpResponse("error")


### get ip attribution: URL
def get_ip_attribution_url(request):
    if request.method == "POST":
        py_body = json.loads(request.body.decode('utf-8'))
        client_ip = py_body["client_ip"]
        #attribution = subprocess.getoutput("curl http://www.cip.cc/" + client_ip + " -s | head -n3")
        response = subprocess.getoutput("curl http://freeapi.ipip.net/" + client_ip + " -s")
        return HttpResponse(response)
    else:
        return HttpResponse("error")


### get 119.29.29.29 resolve result
def get_localdns_result(request):
    if request.method == "POST":
        py_body = json.loads(request.body.decode('utf-8'))
        domain = py_body["domain_name"]
        aaa = request.GET.get("domain_name")
        resolver_result = subprocess.getoutput("dig " + domain + " @119.29.29.29" + " +noall +answer | grep -v \";\" | grep -v '^$'")
        return HttpResponse(aaa)
    else:
        return HttpResponse("error")


### get authority resolve result
# return authority_ns   authority_ip   response

def get_authority_result(request):
    if request.method == "POST":
        py_body = json.loads(request.body.decode('utf-8'))
        domain = py_body["domain_name"]
        client_ip = py_body["client_ip"]
        authority_ns = subprocess.getoutput("dig " + domain + " +trace | grep \"Received\" | tail -n1 | awk '{print $6}' | awk -F '#53' '{print $2}' | sed 's/[()]//g'" )
        authority_ip = subprocess.getoutput("dig " + domain + " +trace | grep \"Received\" | tail -n1 | awk '{print $6}' | awk -F '#53' '{print $1}'")
        if client_ip:
            AnswerRecord = subprocess.getoutput(
                "dig " + domain + " @" + authority_ip + " +client=" + client_ip + " +noall +answer | grep -v \";\" | grep -v '^$'")
            AuthorityRecord = subprocess.getoutput(
                "dig " + domain + " @" + authority_ip + " +client=" + client_ip + " +noall +authority | grep -v \";\" | grep -v '^$'")
            AdditionalRecord = subprocess.getoutput(
                "dig " + domain + " @" + authority_ip + " +client=" + client_ip + " +noall +additional | grep -v \";\" | grep -v '^$'")
            response = {"authority_ns":authority_ns,"authority_ip":authority_ip,"AnswerRecord":AnswerRecord,
                        "AuthorityRecord":AuthorityRecord,"AdditionalRecord":AdditionalRecord}
        else:
            AnswerRecord = subprocess.getoutput(
                "dig " + domain + " @" + authority_ip + " +noall +answer | grep -v \";\" | grep -v '^$'")
            AuthorityRecord = subprocess.getoutput(
                "dig " + domain + " @" + authority_ip + " +noall +authority | grep -v \";\" | grep -v '^$'")
            AdditionalRecord = subprocess.getoutput(
                "dig " + domain + " @" + authority_ip + " +noall +additional | grep -v \";\" | grep -v '^$'")
            response = {"authority_ns": authority_ns, "authority_ip": authority_ip, "AnswerRecord": AnswerRecord,
                        "AuthorityRecord": AuthorityRecord, "AdditionalRecord": AdditionalRecord}
        return HttpResponse(json.dumps(response))
    else:
        return HttpResponse("error")


### get device load
def get_device_load(request):
    if request.method == "POST":
        py_body = json.loads(request.body.decode('utf-8'))
        begtime = unix_time(py_body['begTime'])
        endtime = unix_time(py_body['endTime'])
        attrid = py_body['attrId']
        target_ip = py_body['ip']
        query_body = {"datatype":0,"idtype":1,"begtime":begtime,"endtime":endtime,"query":[{"attrid":attrid,"ip":target_ip}]}
        url = "http://9.94.61.166:28081/api/get_min_data_new/"
        data = json.dumps(query_body)
        response = requests.post(url,data)
        return HttpResponse(response)
    else:
        return HttpResponse("error")


### get dns cache
def get_dns_cache(request):
    pass


### dig request
def customize(request):
    if request.method == "POST":
        py_body = json.loads(request.body.decode('utf-8'))
        if py_body:
            cmd = py_body["cmd"]
            response = subprocess.getoutput(cmd)
            return HttpResponse(response)
        else:
            return HttpResponse("error")


def get_name(request):
    if request.method == "GET":
        pname = request.GET.get("name")
        page = request.GET.get("age")
        response = json.dumps({"name":pname,"age":page})
        return HttpResponse(response)

### support ecs
# def get_ecs_resolve(request):
#     if request.method == "POST":
#         py_body = json.loads(request.body.decode('utf-8'))
#         if py_body:
#             cmd = py_body["cmd"]
#             response = subprocess.getoutput(cmd)
#             return HttpResponse(response)
#         else:
#             return HttpResponse("error")

### query domain information : whois sakaqi.com
    # def domain_information(domain):
    # status_str = str(whois.whois(domain))
    # status_python =json.loads(status_str) #get domian information dict
    # return status_python

#测试，可删除
#status_python = domain_information('sakaqi.com')

# ###获取域名相应的信息，status_python最终是一个dict对象，但是只需要下列几个参数
# domain_name = status_python['domain_name']
# updated_date = status_python['updated_date']
# expiration_date = status_python['expiration_date']
# name_servers = status_python['expiration_date']
# status = status_python['status']
# dnssec = status_python['dnssec']
# whois_server = status_python['whois_server']


### role: dig request
### parameters: domain, dns_server, client
### return: dig response

def dig_request(domain,dns_server=None,client=None):
    if domain is not None:
        if dns_server is None and client is None:
            sh_cmd = 'dig' + ' ' + domain
        elif dns_server is not None and client is None:
            sh_cmd = 'dig' + ' ' + domain + ' ' + '@' + dns_server
        elif dns_server is None and client is not None:
            sh_cmd = 'dig' + ' ' + domain + ' ' + '+client=' + client
        elif dns_server is not None and client is not None:
            sh_cmd = 'dig' + ' ' + domain + ' ' + '@' + dns_server + ' ' + '+client=' + client
        dig_response = subprocess.getoutput(sh_cmd)
        return dig_response
    else:
        return False

### role: get authoritative dns
### parameters: domain

def get_auth_dns(domain):
    sh_cmd = 'dig' + ' ' + domain + ' ' + '+trace'
    re = subprocess.getoutput(sh_cmd)
    return re
#print(get_auth_dns('www.sakaqi.com'))



#sh = dig_request("www.baidu.com","119.29.29.29")
#print(sh)


#assignation client
#eg: dig www.sakaqi.com @client




#a = basic_query('www.baidu.com','A')
#print(a)
#response = os.system("dig www.sakaqi.com")
#response = subprocess.getoutput('dig www.sakaqi.com')
#a = dns.resolver.query('www.sakaqi.com','AAAA','IN',source='49.235.16.147')

# Basic query
#for i in dns.resolver.query('www.baidu.com','A'):
#    print(i)

#for rdata in dns.resolver.query('www.yahoo.com','CNAME') :
#    print(rdata.target)

# Set the DNS Server c cccccccccc
# resolver = dns.resolver.Resolver()
# resolver.nameservers = socket.gethostbyname('ns1.cisco.com')
#
# #print(resolver.nameservers)
# #for rdata in resolver.query('www.yahoo.com', 'CNAME') :
# #    print(rdata.target)
#
# #basic query
# #eg: dig www.sakaqi.com A
# def basic_query(domain,rtype):
#     response = dns.resolver.query(domain,rtype)
#     return response
#
# #assignation local dns
#eg: dig www.sakaqi.com @119.29.29.29 A