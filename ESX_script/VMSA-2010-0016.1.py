# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2010-0016.1"
name = "VMSA-2010-0016.1 : VMware ESXi and ESX third party updates for Service Console and Likewise components"
cve_id = "CVE-2009-0844, CVE-2009-0845, CVE-2009-0846, CVE-2009-4212, CVE-2010-0291, CVE-2010-0307, CVE-2010-0415, CVE-2010-0622, CVE-2010-1087, CVE-2010-1088, CVE-2010-1321, CVE-2010-1437"
description = """a. Service Console OS update for COS kernel
<br>
This patch updates the service console kernel to fix multiple
security issues.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2010-0415, CVE-2010-0307,
CVE-2010-0291, CVE-2010-0622, CVE-2010-1087, CVE-2010-1437, and
CVE-2010-1088 to these issues.
<br>
b. Likewise package updates
<br>
Updates to the likewisekrb5, likewiseopenldap, likewiseopen,
and pamkrb5 packages address several security issues.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2009-0844, CVE-2009-0845,
CVE-2009-0846, CVE-2009-4212, and CVE-2010-1321 to these issues.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2010-0016.html"

flag = 0
if ESX_check('ESX 4.0', 'ESX400-201101401-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201010401-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201010419-SG'):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA