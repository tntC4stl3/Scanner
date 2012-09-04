# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2012-0006.2"
name = "VMSA-2012-0006.2 : VMware Workstation, ESXi, and ESX address several security issues"
cve_id = "CVE-2011-2482, CVE-2011-3191, CVE-2011-4348, CVE-2011-4862, CVE-2012-1515"
description = """a. VMware ROM Overwrite Privilege Escalation
<br>
A flaw in the way port-based I/O is handled allows for modifying
Read-Only Memory that belongs to the Virtual DOS Machine.
Exploitation of this issue may lead to privilege escalation on
Guest Operating Systems that run Windows 2000, Windows XP
32-bit, Windows Server 2003 32-bit or Windows Server 2003 R2
32-bit.
<br>
VMware would like to thank Derek Soeder of Ridgeway Internet
Security, L.L.C. for reporting this issue to us.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2012-1515 to this issue.
<br>
b. ESX third party update for Service Console kernel
<br>
The ESX Service Console Operating System (COS) kernel is updated
to kernel-400.2.6.18-238.4.11.591731 to fix multiple security
issues in the COS kernel.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2011-2482, CVE-2011-3191 and
CVE-2011-4348 to these issues.
<br>
c. ESX third party update for Service Console krb5 RPM
<br>
This patch updates the krb5-libs and krb5-workstation RPMs to
version 1.6.1-63.el5_7 to resolve a security issue.
<br>
By default, the affected krb5-telnet and ekrb5-telnet services
do not run. The krb5 telnet daemon is an xinetd service.  You
can run the following commands to check if krb5 telnetd is
enabled :
/sbin/chkconfig --list krb5-telnet
/sbin/chkconfig --list ekrb5-telnet
<br>
The output of these commands displays if krb5 telnet is enabled.
<br>
You can run the following commands to disable krb5 telnet
daemon :
<br>
/sbin/chkconfig krb5-telnet off
/sbin/chkconfig ekrb5-telnet off
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2011-4862 to this issue.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2012-0006.html"

flag = 0
if ESX_check('ESX 3.5.0', 'ESX350-201203401-SG'):
    flag += 1
if ESX_check('ESX 4.0', 'ESX400-201203401-SG'):
    flag += 1
if ESX_check('ESX 4.0', 'ESX400-201203407-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201101201-SG'):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
