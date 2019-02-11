#!/usr/bin/env python


__author__ = 'Jake Miller (@LaconicWolf)'
__date__ = '20180824'
__version__ = '0.01'
__description__ = '''Leverages the Burp API to scan URLs'''


import os
import time
import sys
import itertools
import re
import argparse
import threading
import socket
from urllib.parse import urlparse
if sys.version.startswith('3'):
    import ipaddress

# Fixes Python3 to Python2 backwards compatability
try:
    import queue
except ImportError:
    import Queue as queue

# Third party modules
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
except ImportError as error:
    missing_module = str(error).split(' ')[-1]
    print('[*] Missing module: {}'.format(missing_module))
    print('[*] Try running "pip install {}", or do an Internet search for installation instructions.'.format(missing_module.strip("'")))
    exit()


def banner():
    """Returns ascii art I modified from: http://www.ascii-art.de/ascii/s/starwars.txt
    and https://www.asciiart.eu/movies/star-wars. I basically put Luke's head on Darth
    Maul's body and made the lightsaber."""
    ascii_art = '''                    
                                 .......        
                                ::::::;;::.     
                              .::;::::;::::.    
      | `                    .::::::::::::::    
    `     /                  ::`_```_```;:::.   
   _  |-\\                    ::=-) :=-`  ::::   
      \\  .  `              `::|  / :     `:::   
    `  .  \\  /               '|  `~'     ;:::   
      _ \\  .                  :-:==-.   / :'    
         .  \\  `              `. _    .'.:    
       `  \\  .  /           _.   |         ._   
         _ .  \\            /  `-              `-.
            \\  .  `      _/  `. \\  \\  :  `.  `.;\\                    
          `  .  \\  /   _/ \\  \\ `-._  /|  `  ._/  \\                   
            _ \\  .    / `. `. `.   /  :    ) \\    |                   
               .  \\   `;._.  \\  _.'/   \\ .' .';   /                   
             `  \\  .  /     .'`._.* /    .-' (   /                   
               _ .  \\'`._  /    ; .' .-'   ;    /                     
                  \\ ;.`._.:     |(    ._   '   /                     
                   ._.\\   ;     ; `.-'        |                     
                     \\ \\ / .-'./ .'  \\ .     /:                     
                     |\\ \\.'  \\ `-.   .\\ *--*' ;\\                    
                     ;.' `. \\ `.    /` `.    /  .                   
                    /.L-'\\_: L__..-*     \\   ".  \\   

                     B u r p  S c a n w a l k e r

                  "The Burp is strong with this one"
'''
    return ascii_art


def ip_range(input_string):
    """Accepts a dash specified range and returns a list of ip addresses
    within that range. Adapted from:
    https://stackoverflow.com/questions/20525330/python-generate-a-list-of-ip-addresses-from-user-input
    """
    octets = input_string.split('.')
    chunks = [list(map(int, octet.split('-'))) for octet in octets]
    ranges = [range(c[0], c[1] + 1) if len(list(c)) == 2 else c for c in chunks]
    addrs = ['.'.join(list(map(str, address))) for address in itertools.product(*ranges)]
    return addrs


def cidr_ip_range(input_string):
    """Accepts a CIDR range and returns a list of ip addresses
    within the CIDR range.
    """
    addr_obj = ipaddress.ip_network(input_string)
    addrs = [str(addr) for addr in addr_obj.hosts()]
    return addrs


def generate_web_addresses(addrs):
    """Takes a list of IP adresses or hostnames and returns a list of URLs
    in http(s)://hostname:port format
    """
    http_port_list = ['80', '280', '81', '591', '593', '2080', '2480', '3080', 
                  '4080', '4567', '5080', '5104', '5800', '6080',
                  '7001', '7080', '7777', '8000', '8008', '8042', '8080',
                  '8081', '8082', '8085', '8088', '8089', '8180', '8222', '8280', '8281',
                  '8530', '8887', '9000', '9080', '9090', '16080']                    
    https_port_list = ['443', '832', '981', '1311', '1443', '2443', '3443', '4443',
                       '5443', '6443', '7002', '7021', '7023', '7025', '7443',
                       '7777', '8333', '8443', '8531', '8888', '9443', '10443']
    web_addrs = []
    for addr in addrs:
        for port in http_port_list:
            web_addrs.append("http://{}:{}".format(addr, port))
        for port in https_port_list:
            web_addrs.append("https://{}:{}".format(addr, port))
    return web_addrs


def normalize_urls(urls):
    """Accepts a list of urls and formats them to the proto://address:port format.
    Returns a new list of the processed urls.
    """
    url_list = []
    http_port_list = ['80', '280', '81', '591', '593', '2080', '2480', '3080', 
                  '4080', '4567', '5080', '5104', '5800', '6080',
                  '7001', '7080', '7777', '8000', '8008', '8042', '8080',
                  '8081', '8082', '8088', '8180', '8222', '8280', '8281',
                  '8530', '8887', '9000', '9080', '9090', '16080']                    
    https_port_list = ['832', '981', '1311', '7002', '7021', '7023', '7025',
                   '7777', '8333', '8531', '8888']
    for url in urls:
        u = urlparse(url)
        if u.scheme == 'http':
            if ':' in u.netloc:
                url_list.append(url)
            else:
                url = u.scheme + '://' + u.netloc + ':80'
                if u.path:
                    url += u.path
                    url_list.append(url)
                else:
                    url_list.append(url)
        elif u.scheme == 'https':
            if ':' in u.netloc:
                url_list.append(url)
                continue
            else:
                url = u.scheme + '://' + u.netloc + ':443'
                if u.path:
                    url += u.path
                    url_list.append(url)
                else:
                    url_list.append(url)
        else:
            if ':' in u.netloc:
                port = u.netloc.split(':')[-1]
                if port in https_port_list:
                    url = 'http://' + url
                    url_list.append(url)
                if port in https_port_list or port.endswith('43'):
                    url = 'https://' + url
                    url_list.append(url)
            while True: 
                scheme = input('[*] Please specify http or https for the site {}, or type exit to quit: '.format(url)).lower()
                if scheme == 'exit':
                    exit()
                if scheme == 'http' or 'https':
                    break
            if scheme == 'http':
                url = scheme + '://' + url
                u = urlparse(url)
                url = u.scheme + '://' + u.netloc + ':80'
                if u.path:
                    url += u.path
                    url_list.append(url)
            if scheme == 'https':
                url = scheme + '://' + url
                u = urlparse(url)
                url = u.scheme + '://' + u.netloc + ':443'
                if u.path:
                    url += u.path
                    url_list.append(url)
            continue
    return url_list


def test_api_connection(api_url):
    """Attempts to connect to the Burp API with a URL that includes the API key."""
    try:
        resp = requests.get(api_url, verify=False)
        if resp.ok:
            return True
        else:
            print('Invalid API URL or Key. Server Response: {}'.format(resp.status_code))
            return False
    except Exception as e:
        if args.debug:
            print('Error: {}'.format(e))
        return False


def start_burp_scan(api_url, url):
    """Initiates request to the Burp API to start a scan for a specified 
    target URL. Scope is limited to the URL by default to prevent going
    out of the scope of the url being scanned.
    """
    # Tests connection to the API. Exits the function if unsuccessful.
    if not test_api_connection(api_url):
        return False
    api_scan_url = api_url.strip('/') + '/scan'
    
    # Automatically sets the scope to the URL. This prevents the scanner
    # to scan out of the scope of the URL you are providing.
    data = {
        "scope": {
            "include": [{"rule": url, "type":"SimpleScopeDef"}]
        }, 
        "urls": [url]
    }
    try:
        if args.proxy:
            resp = requests.post(api_scan_url, json=data, proxies=proxy)
        else:
            resp = requests.post(api_scan_url, json=data)
    except Exception as e:
        if args.debug:
            print(e)
        return False
    if resp.status_code == 201:
        scan_id = resp.headers.get('location')
        return scan_id
    else:
        return False


def scan_with_burp(url):
    """Scans the URL to see if a web service is available, 
    then scans with Burp.
    """
    try:
        resp = requests.get(url, verify=False, timeout=timeout)
    except Exception as e:
        if args.verbose:
            print('Error connecting to {}'.format(url))
        if args.debug:
            print('Error connecting to {}: {}'.format(url, e))
        return
    task_id = start_burp_scan(burp_api_url, url)
    if task_id:
        print('Started scanning {}. Task Id: {}'.format(url, task_id))


def process_queue():
    """Processes the url queue and calls the scan_with_burp function"""
    while True:
        current_url = url_queue.get()
        scan_with_burp(current_url)
        url_queue.task_done()


def main():
    """Normalizes the URLs and starts multithreading"""
    if not test_api_connection(burp_api_url):
        exit()
    processed_urls = normalize_urls(urls)
    
    for i in range(number_of_threads):
        t = threading.Thread(target=process_queue)
        t.daemon = True
        t.start()

    for current_url in processed_urls:
        url_queue.put(current_url)

    url_queue.join()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose",
                        help="Increase output verbosity",
                        action="store_true")
    parser.add_argument("-d", "--debug",
                        help="Show detailed exceptions",
                        action="store_true")
    parser.add_argument("-pr", "--proxy", 
                        help="Specify a proxy to use (-p 127.0.0.1:8080)")
    parser.add_argument("-r", "--range",
                        help="Specify the network range (10.10.10.0/24 or 10.10.10.20-40).")
    parser.add_argument("-uf", "--url_file",
                        help="specify a file containing urls formatted http(s)://addr:port.")
    parser.add_argument("-u", "--url",
                        help="specify a single url formatted http(s)://addr:port.")
    parser.add_argument("-t", "--threads",
                        nargs="?",
                        type=int,
                        const=30,
                        default=30,
                        help="Specify number of threads (default=30)")
    parser.add_argument("-to", "--timeout",
                        nargs="?", 
                        type=int, 
                        default=10, 
                        help="Specify number of seconds until a connection timeout (default=10)")
    parser.add_argument("-a", "--api_address",
                        nargs="?",
                        const='127.0.0.1:1337',
                        default='127.0.0.1:1337',
                        help="Specify the URL of the Burp API in addr:port format (default=127.0.0.1:1337)")
    parser.add_argument("-k", "--key",
                        nargs="?",
                        const='',
                        default='',
                        help="Specify the Burp API key (default=''")
    args = parser.parse_args()

    number_of_threads = args.threads
    timeout = args.timeout
    burp_api_addr = args.api_address
    API_KEY = args.key
    burp_api_url = 'http://{}/{}/v0.1/'.format(burp_api_addr, API_KEY)

    if not args.url and not args.url_file and not args.range:
        parser.print_help()
        print('\n[-] Please specify a single URL (-u) and file containing a list of URLs (-uf) or an IP range (-r)\n')
        exit()
    if args.url and args.url_file:
        parser.print_help()
        print("\n[-] Please specify a URL (-u) or an input file containing URLs (-uf). Not both\n")
        exit()
    if args.url and args.range:
        parser.print_help()
        print("\n[-] Please specify a URL (-u) or a range (-r). Not both\n")
        exit()

    if args.proxy:
        try:
            proxy_host = args.proxy.split(':')[0]
            proxy_port = args.proxy.split(':')[1]
        except IndexError:
            parser.print_help()
            print("\n[-] Error parsing the proxy. Check to make sure the correct format is used. Example -pr 127.0.0.1:8080\n")
            exit()
        proxy = {'http': proxy_host + ':' + proxy_port}
    if args.range and args.url_file:
        parser.print_help()
        print("\n[-] Please specify a range (-r) or an input file containing URLs (-uf). Not both\n")
        exit()
    if args.url:
        urls = [args.url]
    if args.url_file:
        urlfile = args.url_file
        if not os.path.exists(urlfile):
            print("\n[-] The file cannot be found or you do not have permission to open the file. Please check the path and try again\n")
            exit()
        with open(urlfile) as fh:
            urls = fh.read().splitlines()
    if args.range:
        if not '-' in args.range and not '/' in args.range:
            if sys.version.startswith('3'):
                parser.print_help()
                print("\n[-] Please either specify a CIDR range or an octet range with a dash ('-').\n")
                exit()
            else:
                parser.print_help()
                print("\n[-] Please specify an octet range with a dash ('-').\n")
                exit()

        # https://www.regextester.com/93987
        cidr_regex = r'^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$'

        # adapted from https://stackoverflow.com/questions/10086572/ip-address-validation-in-python-using-regex
        dash_regex = r'^[\d+-?]{1,7}\.[\d+-?]{1,7}\.[\d+-?]{1,7}\.[\d+-?]{1,7}$'

        if '-' in args.range:
            if '/' in args.range:
                if sys.version.startswith('3'):
                    parser.print_help()
                    print("\n[-] Please either use CIDR notation or specify octet range with a dash ('-'), not both.\n")
                    exit()
                else:
                    parser.print_help()
                    print("\n[-] CIDR notation not supported with Python2. For CIDR notation, please use Python3.\n")
                    exit()
            if not re.findall(dash_regex, args.range):
                parser.print_help()
                print('\n[-] Invalid IP range detected. Please try again.\n')
                exit()
            ip_addrs = ip_range(args.range)
            # Additional validation to dump any octet larger than 255
            addrs = []
            for addr in ip_addrs:
                octets = str(addr).split('.')
                invalid_addr = [octet for octet in octets if int(octet) > 255]
                if invalid_addr:
                    continue
                addrs.append(addr)
        elif '/' in args.range:
            if sys.version.startswith('2'):
                parser.print_help()
                print(
                    "\n[-] CIDR notation not supported when runnng this script with Python2. For CIDR notation, please use Python3.\n")
                exit()
            try:
                if not re.findall(cidr_regex, args.range):
                    parser.print_help()
                    print('\n[-] Invalid CIDR range detected. Please try again.\n')
                    exit()
                addrs = cidr_ip_range(args.range)
            except ValueError as error:
                parser.print_help()
                print('\n[-] Invalid CIDR range detected. Please try again.')
                print('[-] {}\n'.format(error))
                exit()
        urls = generate_web_addresses(addrs)
        
    print(banner())
    print('By: {}'.format(__author__))
    print(__description__)

    if len(urls) == 1:
        print('\n[*] Loaded {} URL...\n'.format(len(urls)))
    else:
        print('\n[*] Loaded {} URLs...\n'.format(len(urls)))
    time.sleep(3)

    # suppress SSL warnings in the terminal
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    
    # initiates the queue and sets the print lock
    url_queue = queue.Queue()
    print_lock = threading.Lock()
    main()
