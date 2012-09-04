# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2011-0009.3"
name = "VMSA-2011-0009.3 : VMware hosted product updates, ESX patches and VI Client update resolve multiple security issues"
cve_id = "CVE-2009-3080, CVE-2009-4536, CVE-2010-1188, CVE-2010-2240, CVE-2011-1787, CVE-2011-2145, CVE-2011-2146, CVE-2011-2217"
description = """a. VMware vmkernel third party e1000(e) Driver Packet Filter Bypass
<br>
There is an issue in the e1000(e) Linux driver for Intel PRO/1000
adapters that allows a remote attacker to bypass packet filters.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2009-4536 to this issue.
<br>
b. ESX third party update for Service Console kernel
<br>
This update for the console OS kernel package resolves four
security issues.
<br>
1) IPv4 Remote Denial of Service
<br>
An remote attacker can achieve a denial of service via an
issue in the kernel IPv4 code.
<br>
The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2010-1188 to
this issue.
<br>
2) SCSI Driver Denial of Service / Possible Privilege Escalation
<br>
A local attacker can achieve a denial of service and
possibly a privilege escalation via a vulnerability in
the Linux SCSI drivers.
<br>
The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2009-3080 to
this issue.
<br>
3) Kernel Memory Management Arbitrary Code Execution
<br>
A context-dependent attacker can execute arbitrary code
via a vulnerability in a kernel memory handling function.
<br>
The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2010-2240 to
this issue.
<br>
4) e1000 Driver Packet Filter Bypass
<br>
There is an issue in the Service Console e1000 Linux
driver for Intel PRO/1000 adapters that allows a remote
attacker to bypass packet filters.
<br>
The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2009-4536 to
this issue.
<br>
c. Multiple vulnerabilities in mount.vmhgfs
<br>
This patch provides a fix for the following three security
issues in the VMware Host Guest File System (HGFS). None of
these issues affect Windows based Guest Operating Systems.
<br>
1) Mount.vmhgfs Information Disclosure
<br>
Information disclosure via a vulnerability that allows an
attacker with access to the Guest to determine if a path
exists in the Host filesystem and whether it is a file or
directory regardless of permissions.
<br>
The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2011-2146 to
this issue.
<br>
2) Mount.vmhgfs Race Condition
<br>
Privilege escalation via a race condition that allows an
attacker with access to the guest to mount on arbitrary
directories in the Guest filesystem and achieve privilege
escalation if they can control the contents of the
mounted directory.
<br>
The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2011-1787 to
this issue.
<br>
3) Mount.vmhgfs Privilege Escalation
<br>
Privilege escalation via a procedural error that allows
an attacker with access to the guest operating system to
gain write access to an arbitrary file in the Guest
filesystem.  This issue only affects Solaris and FreeBSD
Guest Operating Systems.
<br>
The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2011-2145 to
this issue.
<br>
VMware would like to thank Dan Rosenberg for reporting these
issues.
<br>
d. VI Client ActiveX vulnerabilities
<br>
VI Client COM objects can be instantiated in Internet Explorer
which may cause memory corruption. An attacker who succeeded in
making the VI Client user visit a malicious Web site could
execute code on the user's system within the security context of
that user.
<br>
VMware would like to thank Elazar Broad and iDefense for
reporting this issue to us.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2011-2217 to this issue.
<br>
Affected versions.
<br>
The vSphere Client which comes with vSphere 4.0 and vSphere 4.1
is not affected. This is any build of vSphere Client Version
4.0.0 and vSphere Client Version 4.1.0.
<br>
VI Clients bundled with VMware Infrastructure 3 that are not
affected are :
- VI Client 2.0.2 Build 230598 and higher
- VI Client 2.5 Build 204931 and higher
<br>
The issue can be remediated by replacing an affected VI Client
with the VI Client bundled with VirtualCenter 2.5 Update 6 or
VirtualCenter 2.5 Update 6a.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2011-0009.html"

flag = 0
if ESX_check('ESX 3.5.0', 'ESX350-201105401-SG'):
    flag += 1;
if ESX_check('ESX 3.5.0', 'ESX350-201105404-SG'):
    flag += 1;
if ESX_check('ESX 3.5.0', 'ESX350-201105406-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201104401-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201110410-SG'):
    flag += 1;
if ESX_check('ESX 4.1', 'ESX410-201104401-SG'):
    flag += 1;
if ESX_check('ESX 4.1', 'ESX410-201110225-SG'):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
