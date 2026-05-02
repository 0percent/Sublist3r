#!/usr/bin/env python3
# coding: utf-8
# Sublist3r v3.0 - Enhanced Edition
# Original by Ahmed Aboul-Ela - twitter.com/aboul3la
# Enhanced by Shaheer Yasir

# modules in standard library
import re
import sys
import os
import argparse
import time
import hashlib
import random
import multiprocessing
import threading
import socket
import json
from collections import Counter
from urllib.parse import urlparse, unquote  # Fixed for Python 3

# external modules
from subbrute import subbrute
import dns.resolver
import requests

# Disable SSL warnings
try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

HTTP_DEBUG = True   # master switch for all non-DNSdumpster engines (values: True/False)

# Console Colors (using colorama for cross-platform)
try:
    import colorama
    colorama.init(autoreset=True)
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'   # white
except ImportError:
    print("[!] Install colorama for colored output: pip install colorama")
    G = Y = B = R = W = ''

def no_color():
    global G, Y, B, R, W
    G = Y = B = R = W = ''
        

def banner():
    print(f"""%s
                 ____        _     _ _     _   _____
                / ___| _   _| |__ | (_)___| |_|___ / _ __
                \\___ \\| | | | '_ \\| | / __| __| |_ \\| '__|
                 ___) | |_| | |_) | | \\__ \\ |_ ___) | |
                |____/ \\__,_|_.__/|_|_|___/\\__|____/|_|%s%s

                # Sublist3r v3.0 - Enhanced by Shaheer Yasir (2025)
    """ % (R, W, Y))

def parser_error(errmsg):
    banner()
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print(R + "Error: " + errmsg + W)
    sys.exit(1)

def parse_args():
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -d google.com")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-d', '--domain', help="Domain name to enumerate it's subdomains", required=True)
    parser.add_argument('-b', '--bruteforce', help='Enable the subbrute bruteforce module', nargs='?', default=False)
    parser.add_argument('-p', '--ports', help='Scan the found subdomains against specified tcp ports')
    parser.add_argument('-v', '--verbose', help='Enable Verbosity and display results in realtime', nargs='?', default=False)
    parser.add_argument('-t', '--threads', help='Number of threads to use for subbrute bruteforce', type=int, default=30)
    parser.add_argument('-e', '--engines', help='Specify a comma-separated list of search engines')
    parser.add_argument('-o', '--output', help='Save the results to text file')
    parser.add_argument('-j', '--json', help='Save the results to json file', default=False, action='store_true')
    parser.add_argument('-n', '--no-color', help='Output without color', default=False, action='store_true')
    return parser.parse_args()

def write_file(filename, subdomains, json_output=False):
    print(f"{Y}[-] Saving results to file: {W}{R}{filename}{W}")
    if json_output:
        with open(filename, 'w') as f:
            json.dump(list(subdomains), f, indent=4)
    else:
        with open(filename, 'w') as f:
            for subdomain in subdomains:
                f.write(subdomain + os.linesep)

def subdomain_sorting_key(hostname):
    parts = hostname.split('.')[::-1]
    if parts[-1] == 'www':
        return parts[:-1], 1
    return parts, 0

class DebugSession(requests.Session):
    def request(self, method, url, **kwargs):
        resp = super().request(method, url, **kwargs)

        if HTTP_DEBUG:
            print(f"\n{B}=== HTTP REQUEST ==={W}")
            print(f"{Y}{method}{W} {url}")

            headers = kwargs.get("headers", {})
            if headers:
                print(f"{Y}Request Headers:{W}")
                for k, v in headers.items():
                    print(f"  {k}: {v}")

            data = kwargs.get("data") or kwargs.get("params")
            if data:
                print(f"{Y}Request Data:{W} {data}")

            print(f"{G}=== HTTP RESPONSE ==={W}")
            print(f"{Y}Status:{W} {resp.status_code}")

            print(f"{Y}Response Headers:{W}")
            for k, v in resp.headers.items():
                print(f"  {k}: {v}")

            print(f"{Y}Response Body:{W}")
            print(resp.text)

            print(f"{B}====================={W}\n")

        return resp

class EnumeratorBase(object):
    def __init__(self, base_url, engine_name, domain, subdomains=None, silent=False, verbose=True):
        subdomains = subdomains or []
        self.domain = urlparse(domain).netloc
        #self.session = requests.Session()
        self.session = DebugSession() if HTTP_DEBUG else requests.Session()
        self.subdomains = []
        self.timeout = 25
        self.base_url = base_url
        self.engine_name = engine_name
        self.silent = silent
        self.verbose = verbose
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
        }
        self.print_banner()

    def print_(self, text):
        if not self.silent:
            print(text)
        return

    def print_banner(self):
        self.print_(G + f"[-] Searching now in {self.engine_name}.." + W)
        return

    def send_req(self, query, page_no=1):
        url = self.base_url.format(query=query, page_no=page_no)
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
            resp.raise_for_status()
        except Exception:
            resp = None
        return self.get_response(resp)

    def get_response(self, response):
        if response is None:
            return ""
        return response.text if hasattr(response, "text") else response.content

    def check_max_subdomains(self, count):
        if self.MAX_DOMAINS == 0:
            return False
        return count >= self.MAX_DOMAINS

    def check_max_pages(self, num):
        if self.MAX_PAGES == 0:
            return False
        return num >= self.MAX_PAGES

    def extract_domains(self, resp):
        return

    def check_response_errors(self, resp):
        return True

    def should_sleep(self):
        return

    def generate_query(self):
        return

    def get_page(self, num):
        return num + 10

    def enumerate(self, altquery=False):
        flag = True
        page_no = 0
        prev_links = []
        retries = 0

        while flag:
            query = self.generate_query()
            count = query.count(self.domain)

            if self.check_max_subdomains(count):
                page_no = self.get_page(page_no)

            if self.check_max_pages(page_no):
                return self.subdomains

            resp = self.send_req(query, page_no)

            if not self.check_response_errors(resp):
                return self.subdomains

            links = self.extract_domains(resp)

            if links == prev_links:
                retries += 1
                page_no = self.get_page(page_no)
                if retries >= 3:
                    return self.subdomains

            prev_links = links
            self.should_sleep()

        return self.subdomains

class EnumeratorBaseThreaded(multiprocessing.Process, EnumeratorBase):
    def __init__(self, base_url, engine_name, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        EnumeratorBase.__init__(self, base_url, engine_name, domain, subdomains, silent=silent, verbose=verbose)
        multiprocessing.Process.__init__(self)
        self.q = q
        return

    def run(self):
        domain_list = self.enumerate()
        for domain in domain_list:
            self.q.append(domain)

# GoogleEnum (updated)
class GoogleEnum(EnumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = "https://www.google.com/search?q={query}&start={page_no}"
        self.engine_name = "Google"
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 200
        super(GoogleEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)

        self.headers["Accept-Encoding"] = "identity"

    def extract_domains(self, resp):
        links_list = []
        try:
            # Updated regex for modern Google
            cite_regx = re.compile(r'<div class="g".*?>(.*?)</div>', re.S)
            g_blocks = cite_regx.findall(resp)
            for block in g_blocks:
                cite = re.search(r'<cite.*?>(.*?)</cite>', block, re.S)
                if cite:
                    link = cite.group(1).strip()
                    if link.startswith('/url?q='):
                        link = link[7:].split('&')[0]
                    if not link.startswith('http'):
                        link = "http://" + link
                    subdomain = urlparse(link).netloc
                    if subdomain and subdomain.endswith(self.domain) and subdomain not in self.subdomains and subdomain != self.domain:
                        if self.verbose:
                            self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                        self.subdomains.append(subdomain)
        except Exception:
            pass
        return links_list

    def check_response_errors(self, resp):
        if 'Our systems have detected unusual traffic' in resp:
            self.print_(R + "[!] Error: Google blocking requests" + W)
            return False
        return True

    def should_sleep(self):
        time.sleep(2)
        return

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS - 2])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = f"site:{self.domain} -www.{self.domain}"
        return query

# YahooEnum (from original, updated)
class YahooEnum(EnumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = "https://search.yahoo.com/search?p={query}&b={page_no}"
        self.engine_name = "Yahoo"
        self.MAX_DOMAINS = 10
        self.MAX_PAGES = 0
        super(YahooEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)

    def extract_domains(self, resp):
        link_regx2 = re.compile(r'<span class=" fz-.*? fw-m fc-12th wr-bw.*?">(.*?)</span>')
        link_regx = re.compile(r'<span class="txt"><span class=" cite fw-xl fz-15px">(.*?)</span>')
        links_list = []
        try:
            links = link_regx.findall(resp)
            links2 = link_regx2.findall(resp)
            links_list = links + links2
            for link in links_list:
                link = re.sub(r"<(\/)?b>", "", link)  # Fixed raw string
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse(link).netloc
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list

    def should_sleep(self):
        return

    def get_page(self, num):
        return num + 10

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -domain:www.{domain} -domain:{found}'
            found = ' -domain:'.join(self.subdomains[:77])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain}".format(domain=self.domain)
        return query

# AskEnum (from original)
class AskEnum(EnumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'http://www.ask.com/web?q={query}&page={page_no}&qid=8D6EE6BF52E0C04527E51F64F22C4534&o=0&l=dir&qsrc=998&qo=pagination'
        self.engine_name = "Ask"
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 0
        super(AskEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)

    def extract_domains(self, resp):
        links_list = []
        link_regx = re.compile(r'<p class="web-result-url">(.*?)</p>')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse(link).netloc
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list

    def get_page(self, num):
        return num + 1

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -www.{domain}".format(domain=self.domain)
        return query

# BingEnum (from original)
class BingEnum(EnumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://www.bing.com/search?q={query}&go=Submit&first={page_no}'
        self.engine_name = "Bing"
        self.MAX_DOMAINS = 30
        self.MAX_PAGES = 0
        super(BingEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)

    def extract_domains(self, resp):
        links_list = []
        link_regx = re.compile(r'<li class="b_algo"><h2><a href="(.*?)"')
        link_regx2 = re.compile(r'<div class="b_title"><h2><a href="(.*?)"')
        try:
            links = link_regx.findall(resp)
            links2 = link_regx2.findall(resp)
            links_list = links + links2
            for link in links_list:
                link = re.sub(r'<(\/)?strong>|<span.*?>|<|>', '', link)  # Fixed raw string
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse(link).netloc
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list

    def generate_query(self):
        if self.subdomains:
            fmt = 'domain:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "domain:{domain} -www.{domain}".format(domain=self.domain)
        return query

# BaiduEnum (from original)
class BaiduEnum(EnumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://www.baidu.com/s?pn={page_no}&wd={query}&oq={query}'
        self.engine_name = "Baidu"
        self.MAX_DOMAINS = 2
        self.MAX_PAGES = 760
        super(BaiduEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.querydomain = self.domain

    def extract_domains(self, resp):
        links = []
        found_newdomain = False
        subdomain_list = []
        link_regx = re.compile(r'<a.*?class="c-showurl".*?>(.*?)</a>')
        try:
            links = link_regx.findall(resp)
            for link in links:
                link = re.sub(r'<.*?>|>|<|&nbsp;', '', link)  # Fixed raw string
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse(link).netloc
                if subdomain.endswith(self.domain):
                    subdomain_list.append(subdomain)
                    if subdomain not in self.subdomains and subdomain != self.domain:
                        found_newdomain = True
                        if self.verbose:
                            self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                        self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        if not found_newdomain and subdomain_list:
            self.querydomain = self.findsubs(subdomain_list)
        return links

    def findsubs(self, subdomains):
        count = Counter(subdomains)
        subdomain1 = max(count, key=count.get)
        count.pop(subdomain1, None)
        subdomain2 = max(count, key=count.get) if count else ''
        return (subdomain1, subdomain2)

    def check_response_errors(self, resp):
        return True

    def should_sleep(self):
        time.sleep(random.randint(2, 5))
        return

    def generate_query(self):
        if self.subdomains and self.querydomain != self.domain:
            found = ' -site:'.join(self.querydomain)
            query = "site:{domain} -site:www.{domain} -site:{found} ".format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -site:www.{domain}".format(domain=self.domain)
        return query

# NetcraftEnum (from original, fixed urllib.unquote)
class NetcraftEnum(EnumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        self.base_url = 'https://searchdns.netcraft.com/?restriction=site+ends+with&host={domain}'
        self.engine_name = "Netcraft"
        super(NetcraftEnum, self).__init__(self.base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)

    def req(self, url, cookies=None):
        cookies = cookies or {}
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout, cookies=cookies)
        except Exception as e:
            self.print_(e)
            resp = None
        return resp

    def should_sleep(self):
        time.sleep(random.randint(1, 2))
        return

    def get_next(self, resp):
        link_regx = re.compile(r'<a.*?href="(.*?)">Next Page')
        link = link_regx.findall(resp)
        url = 'http://searchdns.netcraft.com' + link[0]
        return url

    def create_cookies(self, cookie):
        cookies = dict()
        cookies_list = cookie[0:cookie.find(';')].split("=")
        cookies[cookies_list[0]] = cookies_list[1]
        # Fixed for Python 3: use unquote instead of urllib.unquote
        cookies['netcraft_js_verification_response'] = hashlib.sha1(unquote(cookies_list[1]).encode('utf-8')).hexdigest()
        return cookies

    def get_cookies(self, headers):
        if 'set-cookie' in headers:
            cookies = self.create_cookies(headers['set-cookie'])
        else:
            cookies = {}
        return cookies

    def enumerate(self):
        start_url = self.base_url.format(domain='example.com')
        resp = self.req(start_url)
        cookies = self.get_cookies(resp.headers)
        url = self.base_url.format(domain=self.domain)
        while True:
            resp = self.get_response(self.req(url, cookies))
            self.extract_domains(resp)
            if 'Next Page' not in resp:
                break
            url = self.get_next(resp)
            self.should_sleep()
        return self.subdomains

    def extract_domains(self, resp):
        links_list = []
        link_regx = re.compile(r'<a class="results-table__host" href="(.*?)"')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                subdomain = urlparse(link).netloc
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list

# DNSdumpster (modified by Ritesh)
class DNSdumpster(EnumeratorBaseThreaded):
    """
    DNSdumpster Enumerator with FULL HTTP DEBUGGING

    Verbose mode prints:
      - HTTP request (method, URL, headers, cookies, body)
      - HTTP response (status, headers, cookies, body)
    """

    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        self.engine_name = "DNSdumpster"
        self.q = q

        self.base_url = "https://dnsdumpster.com/"
        self.api_url = "https://api.dnsdumpster.com/htmld/"

        super().__init__(
            self.base_url,
            self.engine_name,
            domain,
            subdomains,
            q=q,
            silent=silent,
            verbose=verbose
        )

        self.headers["Accept-Encoding"] = "identity"

    # =========================================================
    # DEBUG HELPERS
    # =========================================================
    def debug_request(self, method, url, headers=None, cookies=None, data=None):
        if not self.verbose:
            return
        print(f"{B}--- HTTP REQUEST --------------------------------{W}")
        print(f"{Y}Method:{W} {method}")
        print(f"{Y}URL:{W} {url}")
        if headers:
            print(f"{Y}Headers:{W}")
            for k, v in headers.items():
                print(f"  {k}: {v}")
        if cookies:
            print(f"{Y}Cookies:{W} {cookies}")
        if data:
            print(f"{Y}Body:{W} {data}")
        print(f"{B}------------------------------------------------{W}")

    def debug_response(self, resp):
        if not self.verbose or not resp:
            return
        print(f"{G}--- HTTP RESPONSE -------------------------------{W}")
        print(f"{Y}Status:{W} {resp.status_code}")
        print(f"{Y}Headers:{W}")
        for k, v in resp.headers.items():
            print(f"  {k}: {v}")
        if resp.cookies:
            print(f"{Y}Cookies:{W} {resp.cookies.get_dict()}")
        print(f"{Y}Body (raw):{W}")
        print(resp.text)
        print(f"{G}------------------------------------------------{W}")

    # =========================================================
    # HTTP METHODS
    # =========================================================
    def http_get(self, url):
        try:
            #below line for debug purpose only
            #self.debug_request("GET", url, headers=self.headers, cookies=self.session.cookies.get_dict())
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
            #below line for debug purpose only
            #self.debug_response(resp)
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            if self.verbose:
                self.print_(f"{R}[!] GET failed: {e}{W}")
            return None

    def http_post(self, url, headers, data):
        try:
            #below line for debug purpose only
            #self.debug_request("POST", url, headers=headers, cookies=self.session.cookies.get_dict(), data=data)
            resp = self.session.post(
                url,
                headers=headers,
                data=data,
                timeout=self.timeout
            )
            #self.debug_response(resp)
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            if self.verbose:
                self.print_(f"{R}[!] POST failed: {e}{W}")
            return None

    # =========================================================
    # TOKEN EXTRACTION
    # =========================================================
    def get_auth_token(self, html):
        if not html:
            return None
        try:
            match = re.search(
                r'hx-headers=[\'"]\{[^}]*"Authorization"\s*:\s*"([^"]+)"',
                html,
                re.IGNORECASE
            )
            if match:
                token = match.group(1)
                #below line for debug purpose only
                '''
                if self.verbose:
                    self.print_(f"{G}[+] Authorization token extracted{W}")
                    self.print_(f"{Y}Token:{W} {token}")
                '''
                return token
        except Exception:
            pass
        
        if self.verbose:
            self.print_(f"{R}[!] Authorization token not found{W}")
        
        return None

    # =========================================================
    # SUBMIT DOMAIN
    # =========================================================
    def submit_domain(self, token):
        headers = dict(self.headers)
        headers.update({
            "Authorization": token,
            "Content-Type": "application/x-www-form-urlencoded",
            "HX-Request": "true",
            "HX-Target": "results",
            "HX-Current-URL": "https://dnsdumpster.com/",
            "Referer": "https://dnsdumpster.com/",
            "Origin": "https://dnsdumpster.com"
        })

        data = {"target": self.domain}
        return self.http_post(self.api_url, headers, data)

    # =========================================================
    # PARSE RESPONSE
    # =========================================================
    def extract_domains(self, html):
        results = []

        if not html:
            return results

        try:
            table_match = re.search(
                r'<table[^>]+id=["\']a_rec_table["\'][\s\S]*?</table>',
                html,
                re.IGNORECASE
            )
            if not table_match:
                if self.verbose:
                    self.print_(f"{Y}[!] a_rec_table not found{W}")
                return results

            table_html = table_match.group(0)

            rows = re.findall(
                r'<tr>([\s\S]*?)</tr>',
                table_html,
                re.IGNORECASE
            )

            for row in rows:
                td_match = re.search(
                    r'<td>\s*([^<\s]+)\s*</td>',
                    row,
                    re.IGNORECASE
                )
                if not td_match:
                    continue

                subdomain = td_match.group(1).strip()

                if (
                    subdomain.endswith(self.domain)
                    and subdomain != self.domain
                    and subdomain not in self.subdomains
                ):
                    self.subdomains.append(subdomain)
                    results.append(subdomain)

                    if self.verbose:
                        self.print_(f"{R}{self.engine_name}: {W}{subdomain}")

        except Exception as e:
            if self.verbose:
                self.print_(f"{R}[!] Parsing error: {e}{W}")

        return results

    # =========================================================
    # MAIN ENUMERATION
    # =========================================================
    def enumerate(self):
        try:
            #below line for debug purpose only
            '''
            if self.verbose:
                self.print_(f"{B}[-] DNSdumpster: Loading landing page{W}")
            '''

            landing_html = self.http_get(self.base_url)
            token = self.get_auth_token(landing_html)
            if not token:
                return self.subdomains

            #below line for debug purpose only
            '''
            if self.verbose:
                self.print_(f"{B}[-] DNSdumpster: Submitting target domain{W}")
            '''

            response_html = self.submit_domain(token)
            self.extract_domains(response_html)

        except Exception as e:
            if self.verbose:
                self.print_(f"{R}[!] Fatal DNSdumpster error: {e}{W}")

        return self.subdomains

# Virustotal (updated to v3)
class Virustotal(EnumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        self.engine_name = "VirusTotal"
        self.q = q
        super(Virustotal, self).__init__('', self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/relationships/subdomains"
        api_key = os.getenv('VT_API_KEY')
        if api_key:
            self.headers['x-apikey'] = api_key
        else:
            self.print_(Y + "[!] No VT_API_KEY set, using public API (rate limited)" + W)

    def send_req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
            resp.raise_for_status()
        except Exception as e:
            self.print_(f"{R}[!] VT Error: {e}{W}")
            resp = None
        return self.get_response(resp)

    def enumerate(self):
        while self.url:
            resp = self.send_req(self.url)
            if not resp:
                break
            try:
                data = json.loads(resp)
                if 'error' in data:
                    self.print_(R + f"[!] VT Error: {data['error']['message']}" + W)
                    break
                if 'data' in data:
                    for item in data['data']:
                        subdomain = item['id']
                        if subdomain.endswith(self.domain) and subdomain not in self.subdomains and subdomain != self.domain:
                            if self.verbose:
                                self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                            self.subdomains.append(subdomain)
                if 'links' in data and 'next' in data['links']:
                    self.url = data['links']['next']
                else:
                    self.url = None
            except json.JSONDecodeError:
                break
            time.sleep(15)  # Rate limit
        return self.subdomains

    def extract_domains(self, resp):
        pass

# ThreatCrowd (from original, note: ThreatCrowd is deprecated, but keeping for compatibility)
class ThreatCrowd(EnumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}'
        self.engine_name = "ThreatCrowd"
        self.q = q
        super(ThreatCrowd, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)

    def req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception:
            resp = None
        return self.get_response(resp)

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.req(url)
        self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        try:
            links = json.loads(resp)['subdomains']
            for link in links:
                subdomain = link.strip()
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            pass

# CrtSearch (from original)
class CrtSearch(EnumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://crt.sh/?q=%25.{domain}'
        self.engine_name = "SSL Certificates"
        self.q = q
        super(CrtSearch, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)

    def req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception:
            resp = None
        return self.get_response(resp)

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.req(url)
        if resp:
            self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        link_regx = re.compile(r'<TD>(.*?)</TD>')
        try:
            links = link_regx.findall(resp)
            for link in links:
                link = link.strip()
                subdomains = []
                if '<BR>' in link:
                    subdomains = link.split('<BR>')
                else:
                    subdomains.append(link)
                for subdomain in subdomains:
                    if not subdomain.endswith(self.domain) or '*' in subdomain:
                        continue
                    if '@' in subdomain:
                        subdomain = subdomain[subdomain.find('@')+1:]
                    if subdomain not in self.subdomains and subdomain != self.domain:
                        if self.verbose:
                            self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                        self.subdomains.append(subdomain.strip())
        except Exception as e:
            pass

# PassiveDNS (from original)
class PassiveDNS(EnumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://api.sublist3r.com/search.php?domain={domain}'
        self.engine_name = "PassiveDNS"
        self.q = q
        super(PassiveDNS, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)

    def req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception as e:
            resp = None
        return self.get_response(resp)

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.req(url)
        if not resp:
            return self.subdomains
        self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        try:
            subdomains = json.loads(resp)
            for subdomain in subdomains:
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            pass

# BufferOverRunEnum (new in v2, kept)
class BufferOverRunEnum(EnumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        self.engine_name = "BufferOverRun"
        self.q = q
        super(BufferOverRunEnum, self).__init__('', self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.url = f"https://dns.bufferover.run/dns?q=.{self.domain}"

    def send_req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
            resp.raise_for_status()
        except Exception:
            resp = None
        return self.get_response(resp)

    def enumerate(self):
        resp = self.send_req(self.url)
        if not resp:
            return self.subdomains
        try:
            data = json.loads(resp)
            all_dns = data.get('FDNS_A', []) + data.get('FDNS_AAAA', [])
            for dns_entry in all_dns:
                parts = [p.strip() for p in dns_entry.split(',')]
                if len(parts) > 1:
                    subdomain = parts[1]
                    if subdomain.endswith(self.domain) and subdomain not in self.subdomains and subdomain != self.domain:
                        if self.verbose:
                            self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                        self.subdomains.append(subdomain)
        except Exception as e:
            self.print_(f"{R}[!] BufferOverRun Error: {e}{W}")
        return self.subdomains

    def extract_domains(self, resp):
        pass

# New for v3.0: CertSpotter
class CertSpotterEnum(EnumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        self.engine_name = "CertSpotter"
        self.q = q
        super(CertSpotterEnum, self).__init__('', self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.url = f"https://certspotter.com/api/v0/certs?domain={self.domain}&expand=dns_names"

    def send_req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
            resp.raise_for_status()
        except Exception:
            resp = None
        return self.get_response(resp)

    def enumerate(self):
        resp = self.send_req(self.url)
        if not resp:
            return self.subdomains
        try:
            data = json.loads(resp)
            for cert in data:
                for dns_name in cert.get('dns_names', []):
                    if dns_name.endswith(self.domain) and dns_name not in self.subdomains and dns_name != self.domain:
                        if self.verbose:
                            self.print_(f"{R}{self.engine_name}: {W}{dns_name}")
                        self.subdomains.append(dns_name)
        except Exception as e:
            self.print_(f"{R}[!] CertSpotter Error: {e}{W}")
        return self.subdomains

    def extract_domains(self, resp):
        pass

class PortScan:
    def __init__(self, subdomains, ports):
        self.subdomains = subdomains
        self.ports = ports
        self.lock = None

    def port_scan(self, host, ports):
        openports = []
        self.lock.acquire()
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((host, int(port)))
                if result == 0:
                    openports.append(port)
                s.close()
            except Exception:
                pass
        self.lock.release()
        if openports:
            print(f"{G}{host}{W} - {R}Found open ports:{W} {Y}{', '.join(openports)}{W}")

    def run(self):
        self.lock = threading.BoundedSemaphore(value=50)
        threads = []
        for subdomain in self.subdomains:
            t = threading.Thread(target=self.port_scan, args=(subdomain, self.ports))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

def main(domain, threads, savefile, ports, silent, verbose, enable_bruteforce, engines, json_output):
    bruteforce_list = set()
    search_list = set()

    subdomains_queue = multiprocessing.Manager().list()

    if enable_bruteforce or enable_bruteforce is None:
        enable_bruteforce = True

    domain_check = re.compile(r"^(http|https)?[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$")
    if not domain_check.match(domain):
        if not silent:
            print(R + "Error: Please enter a valid domain" + W)
        return []

    if not domain.startswith(('http://', 'https://')):
        domain = 'http://' + domain

    parsed_domain = urlparse(domain).netloc

    if not silent:
        print(B + f"[-] Enumerating subdomains now for {parsed_domain}" + W)

    if verbose and not silent:
        print(Y + "[-] Verbosity enabled, showing results in realtime" + W)

    supported_engines = {
        'baidu': BaiduEnum,
        'yahoo': YahooEnum,
        'google': GoogleEnum,
        'bing': BingEnum,
        'ask': AskEnum,
        'netcraft': NetcraftEnum,
        'dnsdumpster': DNSdumpster,
        'virustotal': Virustotal,
        'threatcrowd': ThreatCrowd,
        'crt': CrtSearch,
        'passivedns': PassiveDNS,
        'bufferover': BufferOverRunEnum,
        'certspotter': CertSpotterEnum  # New in v3.0
    }

    chosen_enums = []

    if engines is None:
        chosen_enums = [
            GoogleEnum, BingEnum, YahooEnum, AskEnum, BaiduEnum,
            NetcraftEnum, DNSdumpster, Virustotal, ThreatCrowd,
            CrtSearch, BufferOverRunEnum, PassiveDNS, CertSpotterEnum  # Added CertSpotter
        ]
    else:
        engines_list = [e.lower().strip() for e in engines.split(',')]
        for engine in engines_list:
            if engine in supported_engines:
                chosen_enums.append(supported_engines[engine])

    # Start enumeration
    enums = [enum_class(domain, [], q=subdomains_queue, silent=silent, verbose=verbose) for enum_class in chosen_enums]
    for enum in enums:
        enum.start()
    for enum in enums:
        enum.join()

    subdomains = set(subdomains_queue)
    for subdomain in subdomains:
        search_list.add(subdomain)

    if enable_bruteforce:
        if not silent:
            print(G + "[-] Starting bruteforce with subbrute.." + W)
        path_to_file = os.path.dirname(os.path.realpath(__file__))
        subs_file = os.path.join(path_to_file, 'subbrute', 'names.txt')
        resolvers_file = os.path.join(path_to_file, 'subbrute', 'resolvers.txt')
        process_count = threads
        output = False
        json_out = False
        bruteforce_list = subbrute.print_target(parsed_domain, False, subs_file, resolvers_file, process_count, output, json_out, search_list, verbose)

    all_subdomains = search_list.union(bruteforce_list)

    if all_subdomains:
        all_subdomains = sorted(all_subdomains, key=subdomain_sorting_key)

        if savefile:
            write_file(savefile, all_subdomains, json_output=False)

        if json_output:
            json_filename = f"{parsed_domain}.json"
            write_file(json_filename, all_subdomains, json_output=True)

        if not silent:
            print(Y + f"[-] Total Unique Subdomains Found: {len(all_subdomains)}" + W)

            if not json_output:
                for subdomain in all_subdomains:
                    print(G + subdomain + W)

        if ports:
            if not silent:
                print(G + f"[-] Starting port scan for ports: {Y}{ports}" + W)
            ports_list = ports.split(',')
            pscan = PortScan(all_subdomains, ports_list)
            pscan.run()

    return list(all_subdomains)

def interactive():
    args = parse_args()
    domain = args.domain
    threads = args.threads
    savefile = args.output
    ports = args.ports
    enable_bruteforce = args.bruteforce
    verbose = args.verbose or args.verbose is None
    engines = args.engines
    json_out = args.json
    if args.no_color:
        no_color()
    banner()
    main(domain, threads, savefile, ports, silent=False, verbose=verbose, enable_bruteforce=enable_bruteforce, engines=engines, json_output=json_out)

if __name__ == "__main__":
    interactive()
