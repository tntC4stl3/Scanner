# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2012-0011"
name = "VMSA-2012-0011 : VMware hosted products and ESXi and ESX patches address security issues"
cve_id = "CVE-2012-3288, CVE-2012-3289"
description = """a. VMware Host Checkpoint file memory corruption
<br>
Input data is not properly validated when loading Checkpoint files.
This may allow an attacker with the ability to load a specially
crafted Checkpoint file to execute arbitrary code on the host.
<br>
Workaround
- None identified
<br>
Mitigation
- Do not import virtual machines from untrusted sources.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2012-3288 to this issue.
<br>
b. VMware Virtual Machine Remote Device Denial of Service
<br>
A device (e.g. CD-ROM, keyboard) that is available to a virtual
machine while physically connected to a system that does not run the
virtual machine is referred to as a remote device.
<br>
Traffic coming from remote virtual devices is incorrectly handled.
This may allow an attacker who is capable of manipulating the
traffic from a remote virtual device to crash the virtual machine.
<br>
Workaround
- None identified
<br>
Mitigation
- Users need administrative privileges on the virtual machine
in order to attach remote devices.
- Do not attach untrusted remote devices to a virtual machine.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2012-3289 to this issue.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2012-0011.html"

flag = 0
if ESX_check('ESX 3.5.0', 'ESX350-201206401-SG'):
    flag += 1
if ESX_check('ESX 4.0', 'ESX400-201206401-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201206401-SG'):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
