# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2010-0006.1"
name = "VMSA-2010-0006.1 : ESX Service Console updates for samba and acpid"
cve_id = "CVE-2009-0798, CVE-2009-1888, CVE-2009-2813, CVE-2009-2906, CVE-2009-2948"
description = """a. Service Console update for samba to 3.0.33-3.15.el5_4.1
<br>
This update changes the samba packages to
samba-client-3.0.33-3.15.el5_4.1 and
samba-common-3.0.33-3.15.el5_4.1. These versions include fixes for
security issues that were first fixed in
samba-client-3.0.33-0.18.el4_8 and samba-common-3.0.33-0.18.el4_8.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the names CVE-2009-2906, CVE-2009-1888,CVE-2009-2813
and CVE-2009-2948 to these issues.
<br>
b. Service Console update for acpid to1.0.4-9.el5_4.2
<br>
This updates changes the the acpid package to acpid-1.0.4-9.el5_4.2.
This version includes the fix for a security issue that was first
fixed in acpid-1.0.4-7.el5_4.1.  
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2009-0798 to this issue.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2010-0006.html"

flag = 0

if ESX_check('ESX 4.0', 'ESX400-201003403-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201003405-SG'):
    flag += 1;

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
