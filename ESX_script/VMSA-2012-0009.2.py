# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2012-0009.2"
name = "VMSA-2012-0009.2 : VMware Workstation, Player, Fusion, ESXi and ESX patches address critical security issues"
cve_id = "CVE-2012-1516, CVE-2012-1517, CVE-2012-2448, CVE-2012-2449, CVE-2012-2450"
description = """a. VMware host memory overwrite vulnerability (data pointers)
<br>
Due to a flaw in the handler function for RPC commands, it is
possible to manipulate data pointers within the VMX process.
This vulnerability may allow a guest user to crash the VMX
process or potentially execute code on the host.
<br>
Workaround
<br>
- Configure virtual machines to use less than 4 GB of memory.
Virtual machines that have less than 4GB of memory are not 
affected.
<br>
OR
<br>
- Disable VIX messages from each guest VM by editing the
configuration file (.vmx) for the virtual machine as described
in VMware Knowledge Base article 1714. Add the following line :
isolation.tools.vixMessage.disable = 'TRUE'.
Note: This workaround is not valid for Workstation 7.x and
Fusion 3.x
<br>
Mitigation
<br>
- Do not allow untrusted users access to your virtual machines.
Root or Administrator level permissions are not required to
exploit this issue.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2012-1516 to this issue.
<br>
VMware would like to thank Derek Soeder of Ridgeway Internet
Security, L.L.C. for reporting this issue to us.
<br>
b. VMware host memory overwrite vulnerability (function pointers)
<br>
Due to a flaw in the handler function for RPC commands, it is
possible to manipulate function pointers within the VMX process.
This vulnerability may allow a guest user to crash the VMX
process or potentially execute code on the host.
<br>
Workaround
<br>
- None identified
<br>
Mitigation
<br>
- Do not allow untrusted users access to your virtual machines.
Root or Administrator level permissions are not required to
exploit this issue.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2012-1517 to this issue.
<br>
VMware would like to thank Derek Soeder of Ridgeway Internet
Security, L.L.C. for reporting this issue to us.
<br>
c. ESX NFS traffic parsing vulnerability
<br>
Due to a flaw in the handling of NFS traffic, it is possible to
overwrite memory. This vulnerability may allow a user with
access to the network to execute code on the ESXi/ESX host
without authentication. The issue is not present in cases where
there is no NFS traffic.
<br>
Workaround
- None identified
<br>
Mitigation
- Connect only to trusted NFS servers
- Segregate the NFS network
- Harden your NFS server
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2012-2448 to this issue.
<br>
d. VMware floppy device out-of-bounds memory write
<br>
Due to a flaw in the virtual floppy configuration it is possible
to perform an out-of-bounds memory write. This vulnerability may
allow a guest user to crash the VMX process or potentially
execute code on the host.
<br>
Workaround
<br>
- Remove the virtual floppy drive from the list of virtual IO
devices. The VMware hardening guides recommend removing unused
virtual IO devices in general.
<br>
Mitigation
<br>
- Do not allow untrusted root users in your virtual
machines. Root or Administrator level permissions are required
to exploit this issue.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2012-2449 to this issue.
<br>
e. VMware SCSI device unchecked memory write
<br>
Due to a flaw in the SCSI device registration it is possible to
perform an unchecked write into memory. This vulnerability may
allow a guest user to crash the VMX process or potentially
execute code on the host.
<br>
Workaround
<br>
- Remove the virtual SCSI controller from the list of virtual IO
devices. The VMware hardening guides recommend removing unused
virtual IO devices in general.
<br>
Mitigation
<br>
- Do not allow untrusted root users access to your virtual
machines.  Root or Administrator level permissions are
required to exploit this issue.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2012-2450 to this issue.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2012-0009.html"

flag = 0
if ESX_check('ESX 3.5.0', 'ESX350-201205401-SG'):
    flag += 1
if ESX_check('ESX 4.0', 'ESX400-201105201-UG'):
    flag += 1
if ESX_check('ESX 4.0', 'ESX400-201205401-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201110201-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201201401-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201205401-SG'):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
