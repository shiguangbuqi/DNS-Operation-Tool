# -*-coding: utf8 -*-

import os
import subprocess
import socket
import whois
import json
import urllib.request
import time
import requests

from django.http import HttpResponse

### transform timestamp
def unix_time(dt):
    timeArray = time.strptime(dt, "%Y-%m-%d %H:%M:%S")
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
        #response = subprocess.getoutput("curl http://freeapi.ipip.net/" + client_ip + " -s")
        response = requests.get("http://freeapi.ipip.net/" + client_ip).text
        return HttpResponse(response)
    else:
        return HttpResponse("error")


### get 119.29.29.29 resolve result
def get_localdns_result(request):
    if request.method == "POST":
        py_body = json.loads(request.body.decode('utf-8'))
        domain = py_body["domain_name"]
        res = request.GET.get("domain_name")
        resolver_result = subprocess.getoutput("dig " + domain + " @119.29.29.29" + " +noall +answer | grep -v \";\" | grep -v '^$'")
        return HttpResponse(resolver_result)
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
        url = "http://100.122.28.68:24000/api/get_min_data_new/"
        data = json.dumps(query_body)
        response = requests.post(url,data)
        return HttpResponse(response.text)
    else:
        return HttpResponse("error")


### get dns cache
def get_dns_cache(request):
    pass


### dig request
def customize(request):
    if request.method == "POST":
        py_body = json.loads(request.body.decode('utf-8'))
        cmd = py_body["cmd"]
        response = subprocess.getoutput(cmd)
        return HttpResponse(response)
    else:
        return HttpResponse("error")

