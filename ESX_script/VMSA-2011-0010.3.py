# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2011-0010.3"
name = "VMSA-2011-0010.3 : VMware ESX third party updates for Service Console packages glibc and dhcp"
cve_id = "CVE-2010-0296, CVE-2011-0536, CVE-2011-0997, CVE-2011-1071, CVE-2011-1095, CVE-2011-1658, CVE-2011-1659"
description = """a. Service Console update for DHCP
<br>
The DHCP client daemon, dhclient, does not properly sanatize
certain options in DHCP server replies. An attacker could send a
specially crafted DHCP server reply, that is saved on
the client system and evaluated by a process that assumes the
option is trusted. This could lead to arbitrary code execution
with the privileges of the evaluating process.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2011-0997 to this issue.
<br>
b. Service Console update for glibc
<br>
This patch updates the glibc package for ESX service console to
glibc-2.5-58.7602.vmw. This fixes multiple security issues in
glibc, glibc-common and nscd including possible local privilege
escalation.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the identifiers CVE-2010-0296, CVE-2011-0536,
CVE-2011-1095, CVE-2011-1071, CVE-2011-1658 and CVE-2011-1659 to
these issues.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2011-0010.html"

flag = 0
if ESX_check('ESX 3.5.0', 'ESX350-201203405-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201110406-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201110408-SG'):
    flag += 1;
if ESX_check('ESX 4.1', 'ESX410-201107405-SG'):
    flag += 1;
if ESX_check('ESX 4.1', 'ESX410-201107406-SG'):
    flag += 1;

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
