# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2011-0001.3"
name = "VMSA-2011-0001.3 : VMware ESX third party updates for Service Console packages glibc, sudo, and openldap"
cve_id = "CVE-2010-0211, CVE-2010-0212, CVE-2010-2956, CVE-2010-3847, CVE-2010-3856"
description = """a. Service Console update for glibc
<br>
The service console packages glibc, glibc-common, and nscd are each
updated to version 2.5-34.4908.vmw.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2010-3847 and CVE-2010-3856 to the issues
addressed in this update.
<br>
b. Service Console update for sudo
<br>
The service console package sudo is updated to version
1.7.2p1-8.el5_5.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2010-2956 to the issue addressed in this
update.
<br>
c. Service Console update for openldap
<br>
The service console package openldap is updated to version
2.3.43-12.el5_5.1.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2010-0211 and CVE-2010-0212 to the issues
addressed in this update.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2011-0001.html"

flag = 0
if ESX_check('ESX 4.0', 'ESX400-201101404-SG'):
    flag += 1
if ESX_check('ESX 4.0', 'ESX400-201101405-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201101226-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201104404-SG'):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA