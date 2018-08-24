# Burp-API-Scripts
A collection of scripts used to interact with the Burp Rest API

# scan_with_burp.py
Uses the Burp API to do an active scan on a single host, a file listing hosts, or a range of hosts.

## Usage
By default, the Burp API host is set to 127.0.0.1:1337 and the API is set to ''. Specify the API key with -k.

### Scan a single URL
`python3 scan_with_burp.py -u http://example.com -k <api_key>`

### Scan URLs in a file
`python3 scan_with_burp.py -uf urls.txt -k <api_key>`

### Scan a range of IP addresses
`python3 scan_with_burp.py -r 192.168.0.0/24 -k <api_key>`
or
`python scan_with_burp.py -r 192.168.0.0-255 -k <api_key>`

### Scan URLs in a file and specify a proxy (just for the API call, not the whole scan)
`python3 scan_with_burp.py -uf urls.txt -k <api_key> -pr 127.0.0.1:8080`
