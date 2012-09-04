# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2010-0002.4"
name = "VMSA-2010-0002.4 : VMware vCenter update release addresses multiple security issues in Java JRE"
cve_id = "CVE-2009-1093, CVE-2009-1094, CVE-2009-1095, CVE-2009-1096, CVE-2009-1097, CVE-2009-1098, CVE-2009-1099, CVE-2009-1100, CVE-2009-1101, CVE-2009-1102, CVE-2009-1103, CVE-2009-1104, CVE-2009-1105, CVE-2009-1106, CVE-2009-1107, CVE-2009-2625, CVE-2009-2670, CVE-2009-2671, CVE-2009-2672, CVE-2009-2673, CVE-2009-2675, CVE-2009-2676, CVE-2009-2716, CVE-2009-2718, CVE-2009-2719, CVE-2009-2720, CVE-2009-2721, CVE-2009-2722, CVE-2009-2723, CVE-2009-2724, CVE-2009-3728, CVE-2009-3729, CVE-2009-3864, CVE-2009-3865, CVE-2009-3866, CVE-2009-3867, CVE-2009-3868, CVE-2009-3869, CVE-2009-3871, CVE-2009-3872, CVE-2009-3873, CVE-2009-3874, CVE-2009-3875, CVE-2009-3876, CVE-2009-3877, CVE-2009-3879, CVE-2009-3880, CVE-2009-3881, CVE-2009-3882, CVE-2009-3883, CVE-2009-3884, CVE-2009-3885, CVE-2009-3886"
description = """a. Java JRE Security Update
<br>
JRE update to version 1.5.0_22, which addresses multiple security
issues that existed in earlier releases of JRE.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the following names to the security issues fixed in
JRE 1.5.0_18: CVE-2009-1093, CVE-2009-1094, CVE-2009-1095,
CVE-2009-1096, CVE-2009-1097, CVE-2009-1098, CVE-2009-1099,
CVE-2009-1100, CVE-2009-1101, CVE-2009-1102, CVE-2009-1103,
CVE-2009-1104, CVE-2009-1105, CVE-2009-1106, and CVE-2009-1107.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the following names to the security issues fixed in
JRE 1.5.0_20: CVE-2009-2625, CVE-2009-2670, CVE-2009-2671,
CVE-2009-2672, CVE-2009-2673, CVE-2009-2675, CVE-2009-2676,
CVE-2009-2716, CVE-2009-2718, CVE-2009-2719, CVE-2009-2720,
CVE-2009-2721, CVE-2009-2722, CVE-2009-2723, CVE-2009-2724.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the following names to the security issues fixed in
JRE 1.5.0_22: CVE-2009-3728, CVE-2009-3729, CVE-2009-3864,
CVE-2009-3865, CVE-2009-3866, CVE-2009-3867, CVE-2009-3868,
CVE-2009-3869, CVE-2009-3871, CVE-2009-3872, CVE-2009-3873,
CVE-2009-3874, CVE-2009-3875, CVE-2009-3876, CVE-2009-3877,
CVE-2009-3879, CVE-2009-3880, CVE-2009-3881, CVE-2009-3882,
CVE-2009-3883, CVE-2009-3884, CVE-2009-3886, CVE-2009-3885.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2010-0002.html"

flag = 0

if ESX_check('ESX 3.5.0', 'ESX350-201003403-SG'):
    flag += 1
if ESX_check('ESX 4.0', 'ESX400-201005402-SG'):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
