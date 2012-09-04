# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2010-0010"
name = "VMSA-2010-0010 : ESX 3.5 third party update for Service Console kernel"
cve_id = "CVE-2008-5029, CVE-2008-5300, CVE-2009-1337, CVE-2009-1385, CVE-2009-1895, CVE-2009-2692, CVE-2009-2698, CVE-2009-2848, CVE-2009-3002, CVE-2009-3547"
description = """a. Service Console update for COS kernel
<br>
The service console package kernel is updated to version 2.4.21-63.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2008-5029, CVE-2008-5300, CVE-2009-1337,
CVE-2009-1385, CVE-2009-1895, CVE-2009-2848, CVE-2009-3002, and
CVE-2009-3547 to the security issues fixed in kernel-2.4.21-63.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2009-2698, CVE-2009-2692 to the security
issues fixed in kernel-2.4.21-60.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2010-0010.html"

flag = 0

if ESX_check('ESX 3.5.0', 'ESX350-201006401-SG'):
    flag += 1;

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
