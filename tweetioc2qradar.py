import requests
import json
requests.packages.urllib3.disable_warnings()

tweeturl = "http://www.tweettioc.com/feed/daily/"
dailyioc = "http://www.tweettioc.com/v1/tweets/daily/ioc/"

qradar_server = "<qradar ip>"
QRadar_POST_url = "https://" + qradar_server + "/api/reference_data/sets/bulk_load/"
QRadar_headers = {'SEC': 'xxxxxxx-xxxx-xxxx-xxxx-xxxxxxx', 'Content-Type': 'application/json', 'Version': '9.0', 'Accept':'application/json'}


req = requests.get(dailyioc)
json_data = json.loads(req.text)

def getsha256():
    sha256 = []
    for m in json_data:
        results = (m['sha256'])
        for r in results:
            sha256.append(r)
            sha256 = list(dict.fromkeys(sha256))
    json.dumps(sha256)
    p = requests.post(QRadar_POST_url+"TweetHuntSha256", headers=QRadar_headers, json=sha256, verify=False)


def getmd5():
    md5 = []
    for m in json_data:
        results = (m['md5'])
        for r in results:
            md5.append(r)
            md5 = list(dict.fromkeys(md5))
    json.dumps(md5)
    p = requests.post(QRadar_POST_url+"TweetHuntmd5", headers=QRadar_headers, json=md5, verify=False)

def getdomain():
    domain = []
    for m in json_data:
        results = (m['domain'])
        for r in results:
            domain.append(r)
            domain = list(dict.fromkeys(domain))
    json.dumps(domain)
    p = requests.post(QRadar_POST_url+"TweetHuntdomain", headers=QRadar_headers, json=domain, verify=False)


def getsha1():
    sha1 = []
    for m in json_data:
        results = (m['sha1'])
        for r in results:
            sha1.append(r)
            sha1 = list(dict.fromkeys(sha1))
    json.dumps(sha1)
    p = requests.post(QRadar_POST_url+"TweetHuntsha1", headers=QRadar_headers, json=sha1, verify=False)

def getmail():
    mail = []
    for m in json_data:
        results = (m['mail'])
        for r in results:
            mail.append(r)
            mail = list(dict.fromkeys(mail))
    json.dumps(mail)
    p = requests.post(QRadar_POST_url+"TweetHuntmail", headers=QRadar_headers, json=mail, verify=False)



def getip():
    ip = []
    for m in json_data:
        results = (m['ip'])
        for r in results:
            ip.append(r)
            ip = list(dict.fromkeys(ip))
    json.dumps(ip)
    p = requests.post(QRadar_POST_url+"TweetHuntip", headers=QRadar_headers, json=ip, verify=False)


def geturl():
    url = []
    for m in json_data:
        results = (m['url'])
        for r in results:
            url.append(r)
            url = list(dict.fromkeys(url))
    json.dumps(url)
    p = requests.post(QRadar_POST_url+"TweetHunturl", headers=QRadar_headers, json=url, verify=False)

getsha256()
getmd5()
getdomain()
getsha1()
getmail()
getip()
geturl()
