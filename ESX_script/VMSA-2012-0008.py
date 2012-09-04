# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2012-0008"
name = "VMSA-2012-0008 : VMware ESX updates to ESX Service Console"
cve_id = "CVE-2010-4008, CVE-2011-0216, CVE-2011-1944, CVE-2011-2834, CVE-2011-3191, CVE-2011-3905, CVE-2011-3919, CVE-2011-4348, CVE-2012-0028"
description = """a. ESX third party update for Service Console kernel
<br>
The ESX Service Console Operating System (COS) kernel is updated
which addresses several security issues in the COS kernel.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the names CVE-2011-3191, CVE-2011-4348 and CVE-2012-0028 to
these issues.
<br>
b. Updated ESX Service Console package libxml2
<br>
The ESX Console Operating System (COS) libxml2 rpms are updated to
the following versions libxml2-2.6.26-2.1.12.el5_7.2 and
libxml2-python-2.6.26-2.1.12.el5_7.2 which addresses several
security issues.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the names CVE-2010-4008, CVE-2011-0216, CVE-2011-1944,
CVE-2011-2834, CVE-2011-3905, CVE-2011-3919 to these issues.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2012-0008.html"

flag = 0
if ESX_check('ESX 4.1', 'ESX410-201204401-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201204402-SG'):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
