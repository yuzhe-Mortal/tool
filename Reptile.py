#!/Library/Frameworks/Python.framework/Versions/3.9/bin/python3
# coding=utf-8
# By yz
import time

import requests, argparse, sys, re,hashlib,queue,threading
from requests.packages import urllib3
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin

temp = [".css", ".ico", ".jpg",".png",".vue"]
allurl=[]
allhost=[]
allurl_new=[]
html_md5 = []
js_url = []
url_list=queue.Queue()#待爬取列队
pass_url=""#404页面
content_url = ""
def parse_args():
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -u http://www.baidu.com")
    parser.add_argument("-u", "--url", help="The website")
    parser.add_argument("-c", "--cookie", help="The website cookie")
    parser.add_argument("-f", "--file", help="The file contains url or js")
    parser.add_argument("-ou", "--outputurl", help="Output file name. ")
    parser.add_argument("-os", "--outputsubdomain", help="Output file name. ")
    parser.add_argument("-d", "--deep", help="Deep find", action="store_true")
    parser.add_argument("-t", "--thread", help="Multithreading")
    return parser.parse_args()

# Regular expression comes from https://github.com/GerbenJavado/LinkFinder
def extract_REURL(html):
    pattern_raw = r"""
      ((?:"|')                              # Start newline delimiter
      (
        ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
        [^"'/]{1,}\.                        # Match a domainname (any character + dot)
        [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
        |
        ((?:/|\.\./|\./)                    # Start with /,../,./
        [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
        [^"'><,;|()]{1,})                   # Rest of the characters can't be
        |
        ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
        [a-zA-Z0-9_\-/\.]{1,}                 # Resource name
        \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
        (?:[\?|#][^"|']{0,}|))              # ? mark with parameters
        |
        ([a-zA-Z0-9_\-/]{1,}/
        [a-zA-Z0-9_\-/]{3,}
        (?:[\?|#][^"|']{0,}|))
        |
        ([a-zA-Z0-9_\-]{1,}                 # filename
        \.(?:php|asp|aspx|jsp|json|
             action|html|js|txt|xml|do)             # . + extension
        (?:[\?|#][^"|']{0,}|))                  # ? mark with parameters
      )
      (?:"|')
      |
      (href=[^>\s]*?\.js)
      )                               # End newline delimiter
    """
    pattern = re.compile(pattern_raw, re.VERBOSE)
    result = re.finditer(pattern, str(html))
    if result == None:
        return None

    js_file = ["text/javascript", "text/css", "multipart/form-data", "application/x-www-form-urlencoded",
               "application/json", "text/javascript", "text/javascript", "text/plain", "text/xml", "application/xml",
               "application/pdf","text/html "]
    for match in result:
        match = match.group().strip('"').strip("'").lstrip('href=')
        if match not in js_url and match not in js_file:
            js_url.append(match)
    return js_url

def Extract_html(URL,status_code=False):
    requests.packages.urllib3.disable_warnings()
    md5 = hashlib.md5()
    res_header=[]
    header = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36",
        "Cookie": args.cookie}
    try:
        if "vmobile.douyu.com" in URL:
            return None
        raw_old = requests.get(URL, headers=header, timeout=3, verify=False)
        raw = raw_old.content.decode("utf-8", "ignore")
        md5.update(raw.encode('utf-8'))
        md5_value=md5.hexdigest()
        size=len(raw)
        if raw_old.status_code ==404:
            return None
        if md5_value not in html_md5:
            html_md5.append(md5_value)
        elif status_code==False:
            return None
        if status_code==True:
            res_header.append(str(raw_old.status_code))
            res_header.append(str(size))
            return res_header
        else:
            return raw
    except:
        return None

def find_last(string, str):
    positions = []
    last_position = -1
    while True:
        position = string.find(str, last_position + 1)
        if position == -1: break
        last_position = position
        positions.append(position)
    return positions

def process_url(URL, re_URL):  # 将相对路径转换为URL
    URL_raw = urlparse(URL)  # 拆分URL
    ab_URL = URL_raw.netloc  # 获取域名
    host_URL = URL_raw.scheme  # 获取协议
    path_URL = URL_raw.path
    re_URL= re_URL.split('?')[0]
    try:
        result = urljoin(host_URL + "://" + ab_URL + path_URL, re_URL)
    except:
        return None
    if result!=URL:return result
    else:return None

def find_by_url(url):
    global allurl,allhost
    allurls=[]
    try:
        print("url:" + url)
    except:
        print("Please specify a URL like https://www.baidu.com")
    html_raw = Extract_html(url)
    if html_raw == None:
        print("Fail to access " + url)
        return None
    # print(html_raw)
    re_link = extract_REURL(html_raw)  # 搜索所有的链接
    html_array = {}
    for html_link in re_link:
        link = process_url(url, html_link)  # js的url
        if link==None or link[-4:] in temp:continue
        if link not in allurls:
            allurls.append(link)
    for singerurl in allurls:
        if singerurl == None: continue
        url_raw = urlparse(url)
        domain = url_raw.netloc
        positions = find_last(domain, ".")
        miandomain = domain #url的一级域名
        if len(positions) > 1: miandomain = domain[positions[-2] + 1:]
        suburl = urlparse(singerurl)
        subdomain = suburl.netloc #js的域名
        singerurl=singerurl.strip()
        if miandomain in subdomain:
            if suburl.path[-4:] in temp: continue
            if singerurl not in allurl:
                allurl.append(singerurl)
                if subdomain not in allhost:allhost.append(subdomain)

def find_by_url_deep():
    while allurl_new!=allurl:
        for i in allurl:
            if i not in allurl_new:
                allurl_new.append(i)
                find_by_url(i)

def giveresult():

    content_domain = ""
    resultThread = []
    print("Find "+str(len(allurl))+" URL")
    for url in allurl:
        url_list.put(url)
    for i in range(10):  # 创建线程表
        resultThread.append(threading.Thread(target=url_state_thread))
    for i in resultThread:  # 开启线程表
        i.start()
    for i in resultThread:
        i.join()
    print(pass_url)
    for domain in allhost:
        print("Subdomain:" + domain)
        content_domain += domain + "\n"
    if args.outputurl != None:
        with open(args.outputurl, "a", encoding='utf-8') as fobject:
            fobject.write(content_url)
        print("\nOutput " + str(len(allurl)) + " urls")
        print("Path:" + args.outputurl)
    if args.outputsubdomain != None:
        with open(args.outputsubdomain, "a", encoding='utf-8') as fobject:
            fobject.write(content_domain)
        print("\nOutput " + str(len(allhost)) + " subdomains")
        print("Path:" + args.outputsubdomain)

def find_by_file(file_path):
    with open(file_path, "r") as fobject:
        links = fobject.read().split("\n")
    if links == []: return None
    print("ALL Find " + str(len(links)) + " links")
    i = len(links)
    for link in links:
        find_by_url(link)
        find_by_url_deep()

def url_state_thread():
    global pass_url,content_url
    while not url_list.empty():
        url=url_list.get()
        res_header = Extract_html(url, True)
        if res_header == None:
            pass_url +=url+"\n"
            continue
        print(url + "  状态码：" + res_header[0] + "  szie: " + res_header[1])
        content_url += url + "\n"



if __name__ == "__main__":
    urllib3.disable_warnings()
    args = parse_args()
    if args.file == None:
        if args.deep != True:
            urls = find_by_url(args.url)
            giveresult()
        else:
            result_old = find_by_url(args.url)
            find_by_url_deep()
            giveresult()
    else:
        urls = find_by_file(args.file)
        find_by_url_deep()
        giveresult()


