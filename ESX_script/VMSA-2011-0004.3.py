# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2011-0004.3"
name = "VMSA-2011-0004.3 : VMware ESX/ESXi SLPD denial of service vulnerability and ESX third party updates for Service Console packages bind, pam, and rpm."
cve_id = "CVE-2010-2059, CVE-2010-3316, CVE-2010-3435, CVE-2010-3609, CVE-2010-3613, CVE-2010-3614, CVE-2010-3762, CVE-2010-3853"
description = """a. Service Location Protocol daemon DoS
<br>
This patch fixes a denial-of-service vulnerability in
the Service Location Protocol daemon (SLPD). Exploitation of this
vulnerability could cause SLPD to consume significant CPU
resources.
<br>
VMware would like to thank Nicolas Gregoire and US CERT for
reporting this issue to us.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2010-3609 to this issue.
<br>
b. Service Console update for bind
<br>
This patch updates the bind-libs and bind-utils RPMs to version
9.3.6-4.P1.el5_5.3, which resolves multiple security issues.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2010-3613, CVE-2010-3614, and
CVE-2010-3762 to these issues.
<br>
c. Service Console update for pam
<br>
This patch updates the pam RPM to pam_0.99.6.2-3.27.5437.vmw,
which resolves multiple security issues with PAM modules.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2010-3316, CVE-2010-3435, and
CVE-2010-3853 to these issues.
<br>
d. Service Console update for rpm, rpm-libs, rpm-python, and popt
<br>
This patch updates rpm, rpm-libs, and rpm-python RPMs to
4.4.2.3-20.el5_5.1, and popt to version 1.10.2.3-20.el5_5.1,
which resolves a security issue.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2010-2059 to this issue.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2011-0004.html"

flag = 0
if ESX_check('ESX 4.0', 'ESX400-201103401-SG'):
    flag += 1
if ESX_check('ESX 4.0', 'ESX400-201103404-SG'):
    flag += 1
if ESX_check('ESX 4.0', 'ESX400-201103406-SG'):
    flag += 1
if ESX_check('ESX 4.0', 'ESX400-201103407-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201101201-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201104407-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201110207-SG'):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
