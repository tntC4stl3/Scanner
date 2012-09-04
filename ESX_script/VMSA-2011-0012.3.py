# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2011-0012.3"
name = "VMSA-2011-0012.3 : VMware ESXi and ESX updates to third party libraries and ESX Service Console"
cve_id = "CVE-2010-0296, CVE-2010-1083, CVE-2010-1323, CVE-2010-2492, CVE-2010-2798, CVE-2010-2938, CVE-2010-2942, CVE-2010-2943, CVE-2010-3015, CVE-2010-3066, CVE-2010-3067, CVE-2010-3078, CVE-2010-3086, CVE-2010-3296, CVE-2010-3432, CVE-2010-3442, CVE-2010-3477, CVE-2010-3699, CVE-2010-3858, CVE-2010-3859, CVE-2010-3865, CVE-2010-3876, CVE-2010-3877, CVE-2010-3880, CVE-2010-3904, CVE-2010-4072, CVE-2010-4073, CVE-2010-4075, CVE-2010-4080, CVE-2010-4081, CVE-2010-4083, CVE-2010-4157, CVE-2010-4158, CVE-2010-4161, CVE-2010-4238, CVE-2010-4242, CVE-2010-4243, CVE-2010-4247, CVE-2010-4248, CVE-2010-4249, CVE-2010-4251, CVE-2010-4255, CVE-2010-4263, CVE-2010-4343, CVE-2010-4346, CVE-2010-4526, CVE-2010-4655, CVE-2011-0281, CVE-2011-0282, CVE-2011-0521, CVE-2011-0536, CVE-2011-0710, CVE-2011-1010, CVE-2011-1071, CVE-2011-1090, CVE-2011-1095, CVE-2011-1478, CVE-2011-1494, CVE-2011-1495, CVE-2011-1658, CVE-2011-1659"
description = """a. ESX third party update for Service Console kernel
<br>
This update takes the console OS kernel package to
kernel-2.6.18-238.9.1 which resolves multiple security issues.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the names CVE-2010-1083, CVE-2010-2492, CVE-2010-2798,
CVE-2010-2938, CVE-2010-2942, CVE-2010-2943, CVE-2010-3015,
CVE-2010-3066, CVE-2010-3067, CVE-2010-3078, CVE-2010-3086,
CVE-2010-3296, CVE-2010-3432, CVE-2010-3442, CVE-2010-3477,
CVE-2010-3699, CVE-2010-3858, CVE-2010-3859, CVE-2010-3865,
CVE-2010-3876, CVE-2010-3877, CVE-2010-3880, CVE-2010-3904,
CVE-2010-4072, CVE-2010-4073, CVE-2010-4075, CVE-2010-4080,
CVE-2010-4081, CVE-2010-4083, CVE-2010-4157, CVE-2010-4158,
CVE-2010-4161, CVE-2010-4238, CVE-2010-4242, CVE-2010-4243,
CVE-2010-4247, CVE-2010-4248, CVE-2010-4249, CVE-2010-4251,
CVE-2010-4255, CVE-2010-4263, CVE-2010-4343, CVE-2010-4346,
CVE-2010-4526, CVE-2010-4655, CVE-2011-0521, CVE-2011-0710,
CVE-2011-1010, CVE-2011-1090 and CVE-2011-1478 to these issues.
<br>
b. ESX third party update for Service Console krb5 RPMs
<br>
This patch updates the krb5-libs and krb5-workstation RPMs of the
console OS to version 1.6.1-55.el5_6.1, which resolves multiple
security issues.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the names CVE-2010-1323, CVE-2011-0281, and CVE-2011-0282
to these issues.
<br>
c. ESXi and ESX update to third party component glibc
<br>
The glibc third-party library is updated to resolve multiple
security issues.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the names CVE-2010-0296, CVE-2011-0536, CVE-2011-1071,
CVE-2011-1095, CVE-2011-1658, and CVE-2011-1659 to these issues.
<br>
d. ESX update to third party drivers mptsas, mpt2sas, and mptspi
<br>
The mptsas, mpt2sas, and mptspi drivers are updated which addresses
multiple security issues in the mpt2sas driver.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the names CVE-2011-1494 and CVE-2011-1495 to these issues.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2011-0012.html"

flag = 0
if ESX_check('ESX 3.5.0', 'ESX350-201203403-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201110401-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201110403-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201110409-SG'):
    flag += 1;
if ESX_check('ESX 4.1', 'ESX410-201110201-SG'):
    flag += 1;
if ESX_check('ESX 4.1', 'ESX410-201110224-SG'):
    flag += 1;

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
