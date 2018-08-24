# Burp-API-Scripts
A collection of scripts used to interact with the Burp Rest API

## burp_scanwalker.py
Uses the Burp API to do an active scan on a single host, a file listing hosts, or a range of hosts.

### Usage
Works with Python 3 or Python 2.7. Requires the Requests module. By default, the Burp API host is set to 127.0.0.1:1337 and the API is set to ''. Specify the API key with -k. If you specify a range, the tool will generate an IP range and run each address through a function that creates multiple URLs that attempts connections on multiple web ports. When providing URLs, the format should be http(s)://addr:port. If you don't provide URLs like this, that's okay, the tool will transform your URL to match that format. If the protocol is not specified, the tool will generate http on port 80 and https on port 443.

### Scan a single URL
`python3 burp_scanwalker.py -u http://example.com -k <api_key>`

### Scan URLs in a file
`python3 burp_scanwalker.py -uf urls.txt -k <api_key>`

### Scan a range of IP addresses
`python3 burp_scanwalker.py -r 192.168.0.0/24 -k <api_key>`
or
`python burp_scanwalker.py -r 192.168.0.0-255 -k <api_key>`

### Scan URLs in a file and specify a proxy (just for the API call, not the whole scan)
`python3 burp_scanwalker.py -uf urls.txt -k <api_key> -pr 127.0.0.1:8080`
