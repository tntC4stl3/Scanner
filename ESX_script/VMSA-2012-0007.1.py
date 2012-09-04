# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2012-0007.1"
name = "VMSA-2012-0007.1 : VMware hosted products and ESXi/ESX patches address privilege escalation"
cve_id = "CVE-2012-1518"
description = """a. VMware Tools Incorrect Folder Permissions Privilege Escalation
<br>
The access control list of the VMware Tools folder is incorrectly
set. Exploitation of this issue may lead to local privilege
escalation on Windows-based Guest Operating Systems.
<br>
VMware would like to thank Tavis Ormandy for reporting this issue
to us.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2012-1518 to this issue.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2012-0006.html"

flag = 0
if ESX_check('ESX 4.0', 'ESX400-201203401-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201201401-SG'):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
