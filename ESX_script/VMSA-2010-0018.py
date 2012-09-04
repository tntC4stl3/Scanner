# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2010-0018"
name = "VMSA-2010-0018 : VMware hosted products and ESX patches resolve multiple security issues"
cve_id = "CVE-2010-4294, CVE-2010-4295, CVE-2010-4296, CVE-2010-4297"
description = """a. VMware Workstation, Player and Fusion vmware-mount race condition
<br>
The way temporary files are handled by the mounting process could
result in a race condition. This issue could allow a local user on
the host to elevate their privileges.
<br>
VMware Workstation and Player running on Microsoft Windows are not
affected.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2010-4295 to this issue.
<br>
VMware would like to thank Dan Rosenberg for reporting this issue.
<br>
b. VMware Workstation, Player and Fusion vmware-mount privilege
escalation
<br>
vmware-mount which is a suid binary has a flaw in the way libraries
are loaded.  This issue could allow local users on the host to
execute arbitrary shared object files with root privileges.
<br>
VMware Workstation and Player running on Microsoft Windows are not
affected.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2010-4296 to this issue.
<br>
VMware would like to thank Martin Carpenter for reporting this
issue.
<br>
c. OS Command Injection in VMware Tools update
<br>
A vulnerability in the input validation of VMware Tools update
allows for injection of commands. The issue could allow a  user
on the host to execute commands on the guest operating system
with root privileges.
<br>
The issue can only be exploited if VMware Tools is not fully
up-to-date.  Windows-based virtual machines are not affected.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2010-4297 to this issue.
<br>
VMware would like to thank Nahuel Grisolia of Bonsai Information
Security, http://www.bonsai-sec.com, for reporting this issue.
<br>
d. VMware VMnc Codec frame decompression remote code execution
<br>
The VMware movie decoder contains the VMnc media codec that is
required to play back movies recorded with VMware Workstation,
VMware Player and VMware ACE, in any compatible media player. The
movie decoder is installed as part of VMware Workstation, VMware
Player and VMware ACE, or can be downloaded as a stand alone
package.
<br>
A function in the decoder frame decompression routine implicitly
trusts a size value.  An attacker can utilize this to miscalculate
a destination pointer, leading to the corruption of a heap buffer,
and could allow for execution of arbitrary code with the privileges
of the user running an application utilizing the vulnerable codec.
<br>
For an attack to be successful the user must be tricked into
visiting a malicious web page or opening a malicious video file on
a system that has the vulnerable version of the VMnc codec installed.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2010-4294 to this issue.
<br>
VMware would like to thank Aaron Portnoy and Logan Brown of
TippingPoint DVLabs for reporting this issue.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2010-0018.html"

flag = 0
if ESX_check('ESX 4.0', 'ESX400-201009401-SG'):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA