# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2010-0019.3"
name = "VMSA-2010-0019.3 : VMware ESX third party updates for Service Console"
cve_id = "CVE-2009-0590, CVE-2009-2409, CVE-2009-3555, CVE-2010-0405, CVE-2010-3069"
description = """a. Service Console update for samba
<br>
The service console package samba is updated to version
3.0.9-1.3E.18.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2010-3069 to this issue.
<br>
b. Service Console update for bzip2
<br>
The service console package bzip2 is updated to version
1.0.2-14.EL3 in ESX 3.x and version 1.0.3-6 in ESX
4.x.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2010-0405 to this issue.
<br>
c. Service Console update for OpenSSL
<br>
The service console package openssl updated to version
0.9.7a-33.26.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2009-0590, CVE-2009-2409 and
CVE-2009-3555 to the issues addressed in this update.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2010-0019.html"

flag = 0
if ESX_check('ESX 3.0.3', 'ESX303-201102402-SG'):
    flag += 1
if ESX_check('ESX 3.5.0', 'ESX350-201012401-SG'):
    flag += 1
if ESX_check('ESX 3.5.0', 'ESX350-201012408-SG'):
    flag += 1
if ESX_check('ESX 3.5.0', 'ESX350-201012409-SG'):
    flag += 1
if ESX_check('ESX 4.0', 'ESX400-201103405-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201104403-SG'):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA