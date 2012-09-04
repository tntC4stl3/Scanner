# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2011-0007"
name = "VMSA-2011-0007 : VMware ESXi and ESX Denial of Service and third party updates for Likewise components and ESX Service Console"
cve_id = "CVE-2010-1323, CVE-2010-1324, CVE-2010-2240, CVE-2010-4020, CVE-2010-4021, CVE-2011-1785, CVE-2011-1786"
description = """a. ESX/ESXi Socket Exhaustion
<br>
By sending malicious network traffic to an ESXi or ESX host an
attacker could exhaust the available sockets which would prevent
further connections to the host. In the event a host becomes
inaccessible its virtual machines will continue to run and have
network connectivity but a reboot of the ESXi or ESX host may be
required in order to be able to connect to the host again.
<br>
ESXi and ESX hosts may intermittently lose connectivity caused by
applications that do not correctly close sockets. If this occurs an
error message similar to the following may be written to the vpxa
log :
<br>
socket() returns -1 (Cannot allocate memory)
<br>
An error message similar to the following may be written to the
vmkernel logs :
<br>
socreate(type=2, proto=17) failed with error 55
<br>
VMware would like to thank Jimmy Scott at inet-solutions.be for
reporting this issue to us.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org) has
assigned the name CVE-2011-1785 to this issue.
<br>
b. Likewise package update
<br>
Updates to the vmware-esx-likewise-openldap and
vmware-esx-likewise-krb5 packages address several security issues.
<br>
One of the vulnerabilities is specific to Likewise while the other
vulnerabilities are present in the MIT version of krb5.
An incorrect assert() call in Likewise may lead to a termination
of the Likewise-open lsassd service if a username with an illegal
byte sequence is entered for user authentication when logging in to
the Active Directory domain of the ESXi/ESX host. This would lead to
a denial of service.
The MIT-krb5 vulnerabilities are detailed in MITKRB5-SA-2010-007.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the names CVE-2011-1786 (Likewise-only issue),
CVE-2010-1324, CVE-2010-1323, CVE-2010-4020, CVE-2010-4021 to these
issues.
<br>
c. ESX third party update for Service Console kernel
<br>
The Service Console kernel is updated to include a fix for a
security issue.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2010-2240 to this issue.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2011-0007.html"

flag = 0
if ESX_check('ESX 4.0', 'ESX400-201104401-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201104401-SG'):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
