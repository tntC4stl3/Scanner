# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2010-0017.1"
name = "VMSA-2010-0017.1 : VMware ESX third party update for Service Console kernel"
cve_id = "CVE-2010-0291, CVE-2010-0307, CVE-2010-0415, CVE-2010-0622, CVE-2010-1087, CVE-2010-1088, CVE-2010-1437, CVE-2010-3081"
description = """a. Service Console OS update for COS kernel package.
<br>
This patch updates the Service Console kernel to fix a stack
pointer underflow issue in the 32-bit compatibility layer.
<br>
Exploitation of this issue could allow a local user to gain
additional privileges.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2010-3081 to this issue.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2010-0017.html"

flag = 0
if ESX_check('ESX 4.0', 'ESX400-201101401-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201011402-SG'):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA