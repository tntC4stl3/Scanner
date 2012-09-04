# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2011-0008"
name = "VMSA-2011-0008 : VMware vCenter Server and vSphere Client security vulnerabilities"
cve_id = "CVE-2011-0426, CVE-2011-1788, CVE-2011-1789"
description = """a. vCenter Server Directory Traversal vulnerability
<br>
A directory traversal vulnerability allows an attacker to remotely
retrieve files from vCenter Server without authentication. In order
to exploit this vulnerability, the attacker will need to have access
to the network on which the vCenter Server host resides.
<br>
In case vCenter Server is installed on Windows 2008 or
Windows 2008 R2, the security vulnerability is not present.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2011-0426 to this issue.
<br>
b. vCenter Server SOAP ID disclosure
<br>
The SOAP session ID can be retrieved by any user that is logged in
to vCenter Server. This might allow a local unprivileged user on
vCenter Server to elevate his or her privileges.
<br>
VMware would like to thank Claudio Criscione for reporting this
issue to us.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2011-1788 to this issue.
<br>
c. vSphere Client Installer package not digitally signed
<br>
The digitally signed vSphere Client installer is packaged in a
self-extracting installer package which is not digitally signed. As
a result, when you run the install package file to extract and start
installing, the vSphere Client installer may display a Windows
warning message stating that the publisher of the install package
cannot be verified.
<br>
The vSphere Client Installer package of the following product
versions is now digitally signed :
<br>
vCenter Server 4.1 Update 1
vCenter Server 4.0 Update 3
<br>
ESXi 4.1 Update 1
ESXi 4.0 with patch ESXi400-201103402-SG
<br>
ESX 4.1 Update 1
ESX 4.0 with patch ESX400-201103401-SG
<br>
An install or update of the vSphere Client from these releases will
not present a security warning from Windows.
Note: typically the vSphere Client will request an update if the
existing client is pointed at a newer version of vCenter or ESX.
<br>
VMware Knowledge Base article 1021404 explains how the unsigned
install package can be obtained in an alternative, secure way for an
environment with VirtualCenter 2.5, ESXi/ESX 3.5 or ESX 3.0.3.
<br>
VMware would like to thank Claudio Criscione for reporting this
issue to us.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2011-1789 to this issue.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2011-0008.html"

flag = 0
if ESX_check('ESX 4.0', 'ESX400-201103401-SG'):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
