#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This script performs the necessary actions for collecting the latest IP addresses used by Amazon
Web Services, Google Compute, and Microsoft Azure. At the end, all IP addresses are output to
a CloudIPs.txt file. Each range is printed on a new line following a header naming the provider.
"""

import requests
import json
import dns.resolver
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET

# Setup the DNS resolver without a short timeout
resolver = dns.resolver.Resolver()
resolver.timeout = 1
resolver.lifetime = 1

# The addresses listed in the providers' documentation for the latest addresses
aws_uri =  "https://ip-ranges.amazonaws.com/ip-ranges.json"
azure_uri = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653"
compute_uri = "_cloud-netblocks.googleusercontent.com"

# Lists for holding the IP address ranges as they are collected
aws_addresses = []
azure_addresses = []
compute_addresses = []

def get_dns_record(domain, record_type):
    """Simple function to get the specified DNS record for the target domain."""
    answer = resolver.query(domain, record_type)
    return answer


# Fetch the JSON for the latest AWS IP ranges
try:
    aws_json = requests.get(aws_uri).json()
except:
    print("[!] Failed to get the AWS IP addresses!")

if aws_json:
    print("[+] Collected AWS IP ranges last updated on %s" % aws_json['createDate'])
    for address in aws_json['prefixes']:
        aws_addresses.append(address['ip_prefix'])

# Find the current address for the latest Azure XML document from Microsoft Download Center
try:
    azure_req = requests.get(azure_uri)
except:
    print("[!] Failed to get the Azure XML file from Microsoft Download Center!")

soup = BeautifulSoup(azure_req.text, features="html.parser")
for link in soup.find_all('a', href=True):
    if "PublicIPs" in link['href']:
        azure_uri = link['href']

# Fetch the XML for the latest Azure IP ranges
print("[+] Found Microsoft link for the XML document: %s" % azure_uri)
try:
    azure_xml = requests.get(azure_uri).content
    # Parse the Azure XML for the IP ranges
    tree = ET.fromstring(azure_xml)
    # root = tree.getroot()
    for child in tree:
        for address in child:
            azure_addresses.append(address.attrib['Subnet'])
except:
    print("[!] Failed to get the Azure XML file from Microsoft Download Center!")

# Begin the TXT record collection for Google Compute
# First, the hostnames must be collected from the primary _cloud-netblocks subdomain
try:
    txt_records = get_dns_record(compute_uri, "TXT")
    for rdata in txt_records.response.answer:
        for item in rdata.items:
            netblock_names = item.to_text().strip('"').strip("v=spf1 include:").strip(" ?all")
except:
    netblock_names = None

# Now the TXT records of each of the netblocks subdomains must be collected
if netblock_names:
    netblocks = netblock_names.split(" ")
    for hostname in netblocks:
        print("[+] Collecting TXT records for %s" % hostname.strip("include:"))
        txt_records = get_dns_record(hostname.strip("include:"), "TXT")

        txt_entries = []
        for rdata in txt_records.response.answer:
            for item in rdata.items:
                txt_entries = item.to_text().strip('"').strip("v=spf1 ").split(" ")

            for entry in txt_entries:
                if "include" in entry:
                    netblocks.append(entry)

                if "ip" in entry:
                    address = entry.strip("ip4:").strip("ip6:")
                    compute_addresses.append(address)

# Output an up-to-date list of all cloud IP address ranges for all three providers
with open("CloudIPs.txt", "w") as output_file:
    output_file.write("# Amazon Web Services IPs\n\n")
    for address in aws_addresses:
        output_file.write(address + "\n")

    output_file.write("\n")

    output_file.write("# Microsft Azure IPs\n\n")
    for address in azure_addresses:
        output_file.write(address + "\n")

    output_file.write("\n")

    output_file.write("# Google Compute IPs\n\n")
    for address in compute_addresses:
        output_file.write(address + "\n")
    