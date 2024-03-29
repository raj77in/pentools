#!/usr/bin/python3

import sys
import requests
from bs4 import BeautifulSoup

domain = "%25." + sys.argv[1]
url = "https://crt.sh/?q=" + domain

print("Getting the details from crt.sh")
resp = requests.get(url)

print("Extracting the details from the output")
soup = BeautifulSoup(resp.content, "html.parser")
urls = []
for i in soup.select("table tr td:nth-of-type(5)"):
    if not "*" in i.text:
        urls.append(i.text)

print("Unique domains from " + url)
for i in sorted(set(urls)):
    print(i)
