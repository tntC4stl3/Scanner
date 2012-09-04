# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2012-0003"
name = "VMSA-2012-0003 : VMware VirtualCenter Update and ESX 3.5 patch update JRE"
cve_id = "CVE-2011-3389, CVE-2011-3516, CVE-2011-3521, CVE-2011-3544, CVE-2011-3545, CVE-2011-3546, CVE-2011-3547, CVE-2011-3548, CVE-2011-3549, CVE-2011-3550, CVE-2011-3551, CVE-2011-3552, CVE-2011-3553, CVE-2011-3554, CVE-2011-3555, CVE-2011-3556, CVE-2011-3557, CVE-2011-3558, CVE-2011-3560, CVE-2011-3561"
description = """a. VirtualCenter and ESX, Oracle (Sun) JRE update 1.5.0_32
<br>
Oracle (Sun) JRE is updated to version 1.5.0_32, which addresses
multiple security issues that existed in earlier releases of Oracle
(Sun) JRE.
<br>
Oracle has documented the CVE identifiers that are addressed in
JRE 1.5.0_32 in the Oracle Java SE Critical Patch Update Advisory of
October 2011.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2012-0003.html"

flag = 0
if ESX_check('ESX 3.5.0', 'ESX350-201203401-SG'):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
