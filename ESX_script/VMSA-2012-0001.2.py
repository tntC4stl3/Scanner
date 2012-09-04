# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2012-0001.2"
name = "VMSA-2012-0001.2 : VMware ESXi and ESX updates to third party library and ESX Service Console"
cve_id = "CVE-2009-3560, CVE-2009-3720, CVE-2010-0547, CVE-2010-0787, CVE-2010-1634, CVE-2010-2059, CVE-2010-2089, CVE-2010-3493, CVE-2010-4649, CVE-2011-0695, CVE-2011-0711, CVE-2011-0726, CVE-2011-1015, CVE-2011-1044, CVE-2011-1078, CVE-2011-1079, CVE-2011-1080, CVE-2011-1093, CVE-2011-1163, CVE-2011-1166, CVE-2011-1170, CVE-2011-1171, CVE-2011-1172, CVE-2011-1182, CVE-2011-1494, CVE-2011-1495, CVE-2011-1521, CVE-2011-1573, CVE-2011-1576, CVE-2011-1577, CVE-2011-1593, CVE-2011-1678, CVE-2011-1745, CVE-2011-1746, CVE-2011-1763, CVE-2011-1776, CVE-2011-1780, CVE-2011-1936, CVE-2011-2022, CVE-2011-2192, CVE-2011-2213, CVE-2011-2482, CVE-2011-2491, CVE-2011-2492, CVE-2011-2495, CVE-2011-2517, CVE-2011-2519, CVE-2011-2522, CVE-2011-2525, CVE-2011-2689, CVE-2011-2694, CVE-2011-2901, CVE-2011-3378"
description = """a. ESX third party update for Service Console kernel
<br>
The ESX Service Console Operating System (COS) kernel is updated to
kernel-2.6.18-274.3.1.el5 to fix multiple security issues in the
COS kernel.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the names CVE-2011-0726, CVE-2011-1078, CVE-2011-1079,
CVE-2011-1080, CVE-2011-1093, CVE-2011-1163, CVE-2011-1166,
CVE-2011-1170, CVE-2011-1171, CVE-2011-1172, CVE-2011-1494,
CVE-2011-1495, CVE-2011-1577, CVE-2011-1763, CVE-2010-4649,
CVE-2011-0695, CVE-2011-0711, CVE-2011-1044, CVE-2011-1182,
CVE-2011-1573, CVE-2011-1576, CVE-2011-1593, CVE-2011-1745,
CVE-2011-1746, CVE-2011-1776, CVE-2011-1936, CVE-2011-2022,
CVE-2011-2213, CVE-2011-2492, CVE-2011-1780, CVE-2011-2525,
CVE-2011-2689, CVE-2011-2482, CVE-2011-2491, CVE-2011-2495,
CVE-2011-2517, CVE-2011-2519, CVE-2011-2901 to these issues.
<br>
b. ESX third party update for Service Console cURL RPM
<br>
The ESX Service Console (COS) curl RPM is updated to cURL-7.15.5.9
resolving a security issues.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2011-2192 to this issue.
<br>
c. ESX third party update for Service Console nspr and nss RPMs
<br>
The ESX Service Console (COS) nspr and nss RPMs are updated to
nspr-4.8.8-1.el5_7 and nss-3.12.10-4.el5_7 respectively resolving
a security issues.
<br>
A Certificate Authority (CA) issued fraudulent SSL certificates and
Netscape Portable Runtime (NSPR) and Network Security Services (NSS)
contain the built-in tokens of this fraudulent Certificate
Authority. This update renders all SSL certificates signed by the
fraudulent CA as untrusted for all uses.
<br>
d. ESX third party update for Service Console rpm RPMs
<br>
The ESX Service Console Operating System (COS) rpm packages are
updated to popt-1.10.2.3-22.el5_7.2, rpm-4.4.2.3-22.el5_7.2,
rpm-libs-4.4.2.3-22.el5_7.2 and rpm-python-4.4.2.3-22.el5_7.2
which fixes multiple security issues.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the names CVE-2010-2059 and CVE-2011-3378 to these
issues.
<br>
e. ESX third party update for Service Console samba RPMs
<br>
The ESX Service Console Operating System (COS) samba packages are
updated to samba-client-3.0.33-3.29.el5_7.4,
samba-common-3.0.33-3.29.el5_7.4 and
libsmbclient-3.0.33-3.29.el5_7.4 which fixes multiple security
issues in the Samba client.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the names CVE-2010-0547, CVE-2010-0787, CVE-2011-1678,
CVE-2011-2522 and CVE-2011-2694 to these issues.
<br>
Note that ESX does not include the Samba Web Administration Tool
(SWAT) and therefore ESX COS is not affected by CVE-2011-2522 and
CVE-2011-2694.
<br>
f. ESX third party update for Service Console python package
<br>
The ESX Service Console (COS) python package is updated to
2.4.3-44 which fixes multiple security issues.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the names CVE-2009-3720, CVE-2010-3493, CVE-2011-1015 and
CVE-2011-1521 to these issues.
<br>
g. ESXi update to third party component python
<br>
The python third party library is updated to python 2.5.6 which
fixes multiple security issues.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the names CVE-2009-3560, CVE-2009-3720, CVE-2010-1634,
CVE-2010-2089, and CVE-2011-1521 to these issues.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2012-0001.html"

flag = 0
if ESX_check('ESX 4.0', 'ESX400-201203401-SG'):
    flag += 1
if ESX_check('ESX 4.0', 'ESX400-201203402-SG'):
    flag += 1
if ESX_check('ESX 4.0', 'ESX400-201203403-SG'):
    flag += 1
if ESX_check('ESX 4.0', 'ESX400-201203404-SG'):
    flag += 1
if ESX_check('ESX 4.0', 'ESX400-201203405-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201201401-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201201402-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201201404-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201201405-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201201406-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201201407-SG'):
    flag += 1


if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
