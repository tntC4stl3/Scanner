# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2010-0001.1"
name = "VMSA-2010-0001.1 : ESX Service Console and vMA updates for nss and nspr"
cve_id = "CVE-2009-0689, CVE-2009-2404, CVE-2009-2408, CVE-2009-2409, CVE-2009-3274, CVE-2009-3370, CVE-2009-3372, CVE-2009-3373, CVE-2009-3374, CVE-2009-3375, CVE-2009-3376, CVE-2009-3380, CVE-2009-3382"
description = """a. Service Console update for NSS_db
<br>
The service console package NSS_db is updated to version
nss_db-2.2-35.4.el5_5.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2010-0826 to this issue.
<br>
b. Service Console update for OpenLDAP
<br>
The service console package OpenLDAP updated to version
2.3.43-12.el5.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2009-3767 to this issue.
<br>
c. Service Console update for cURL
<br>
The service console packages for cURL updated to version
7.15.5-9.el5.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2010-0734 to this issue.
<br>
d. Service Console update for sudo
<br>
The service console package sudo updated to version 1.7.2p1-7.el5_5.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2010-1646 to this issue.
<br>
e. Service Console update for OpenSSL, GnuTLS, NSS and NSPR
<br>
Service Console updates for OpenSSL to version 097a-0.9.7a-9.el5_4.2
and version 0.9.8e-12.el5_4.6, GnuTLS to version 1.4.1-3.el5_4.8,
and NSS to version 3.12.6-1.3235.vmw and NSPR to version
4.8.4-1.3235.vmw. These four updates are bundled together due to
their mutual dependencies.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2009-3555, CVE-2009-2409, CVE-2009-3245
and CVE-2010-0433 to the issues addressed in this update.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2010-0001.html"

flag = 0

if ESX_check('ESX 4.0', 'ESX400-201009401-SG'):
    flag += 1
if ESX_check('ESX 4.0', 'ESX400-201009407-SG'):
    flag += 1
if ESX_check('ESX 4.0', 'ESX400-201009408-SG'):
    flag += 1
if ESX_check('ESX 4.0', 'ESX400-201009409-SG'):
    flag += 1
if ESX_check('ESX 4.0', 'ESX400-201009410-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201010402-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201010404-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201010410-SG'):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
