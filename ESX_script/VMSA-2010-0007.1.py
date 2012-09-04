# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2010-0007.1"
name = "VMSA-2010-0007.1 : VMware hosted products, vCenter Server and ESX patches resolve multiple security issues"
cve_id = "CVE-2009-1564, CVE-2009-1565, CVE-2009-2042, CVE-2009-3707, CVE-2009-3732, CVE-2009-4811, CVE-2010-1138, CVE-2010-1139, CVE-2010-1140, CVE-2010-1141, CVE-2010-1142"
description = """a. Windows-based VMware Tools Unsafe Library Loading vulnerability
<br>
A vulnerability in the way VMware libraries are referenced allows
for arbitrary code execution in the context of the logged on user.
This vulnerability is present only on Windows Guest Operating
Systems.
<br>
In order for an attacker to exploit the vulnerability, the attacker
would need to lure the user that is logged on a Windows Guest
Operating System to click on the attacker's file on a network
share. This file could be in any file format. The attacker will
need to have the ability to host their malicious files on a
network share.
<br>
VMware would like to thank Jure Skofic and Mitja Kolsek of ACROS
Security (http://www.acrossecurity.com) for reporting this issue
to us.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2010-1141 to this issue.
<br>
Steps needed to remediate this vulnerability :
<br>
Guest systems on VMware Workstation, Player, ACE, Server, Fusion
- Install the remediated version of Workstation, Player, ACE,
Server and Fusion.
- Upgrade tools in the virtual machine (virtual machine users
will be prompted to upgrade).
<br>
Guest systems on ESX 4.0, 3.5, 3.0.3, 2.5.5, ESXi 4.0, 3.5
- Install the relevant patches (see below for patch identifiers)
- Manually upgrade tools in the virtual machine (virtual machine
users will not be prompted to upgrade).  Note the VI Client will
not show the VMware tools is out of date in the summary tab.
Please see http://tinyurl.com/27mpjo page 80 for details.
<br>
b. Windows-based VMware Tools Arbitrary Code Execution vulnerability
<br>
A vulnerability in the way VMware executables are loaded allows for
arbitrary code execution in the context of the logged on user. This
vulnerability is present only on Windows Guest Operating Systems.
<br>
In order for an attacker to exploit the vulnerability, the attacker
would need to be able to plant their malicious executable in a
certain location on the Virtual Machine of the user.  On most
recent versions of Windows (XP, Vista) the attacker would need to
have administrator privileges to plant the malicious executable in
the right location.
<br>
Steps needed to remediate this vulnerability: See section 3.a.
<br>
VMware would like to thank Mitja Kolsek of ACROS Security
(http://www.acrossecurity.com) for reporting this issue to us.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2010-1142 to this issue.
<br>
Refer to the previous table in section 3.a for what action
remediates the vulnerability (column 4) if a solution is
available. See above for remediation details.
<br>
c. Windows-based VMware Workstation and Player host privilege
escalation
<br>
A vulnerability in the USB service allows for a privilege
escalation. A local attacker on the host of a Windows-based
Operating System where VMware Workstation or VMware Player
is installed could plant a malicious executable on the host and
elevate their privileges.
<br>
In order for an attacker to exploit the vulnerability, the attacker
would need to be able to plant their malicious executable in a
certain location on the host machine.  On most recent versions of
Windows (XP, Vista) the attacker would need to have administrator
privileges to plant the malicious executable in the right location.
<br>
VMware would like to thank Thierry Zoller for reporting this issue
to us.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2010-1140 to this issue.
<br>
d. Third party library update for libpng to version 1.2.37
<br>
The libpng libraries through 1.2.35 contain an uninitialized-
memory-read bug that may have security implications.
Specifically, 1-bit (2-color) interlaced images whose widths are
not divisible by 8 may result in several uninitialized bits at the
end of certain rows in certain interlace passes being returned to
the user. An application that failed to mask these out-of-bounds
pixels might display or process them, albeit presumably with benign
results in most cases.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2009-2042 to this issue.
<br>
e. VMware VMnc Codec heap overflow vulnerabilities
<br>
The VMware movie decoder contains the VMnc media codec that is
required to play back movies recorded with VMware Workstation,
VMware Player and VMware ACE, in any compatible media player. The
movie decoder is installed as part of VMware Workstation, VMware
Player and VMware ACE, or can be downloaded as a stand alone
package.
<br>
Vulnerabilities in the decoder allow for execution of arbitrary
code with the privileges of the user running an application
utilizing the vulnerable codec.
<br>
For an attack to be successful the user must be tricked into
visiting a malicious web page or opening a malicious video file on
a system that has the vulnerable version of the VMnc codec installed.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2009-1564 and CVE-2009-1565 to these
issues.
<br>
VMware would like to thank iDefense, Sebastien Renaud of VUPEN
Vulnerability Research Team (http://www.vupen.com) and Alin Rad Pop
of Secunia Research for reporting these issues to us.
<br>
To remediate the above issues either install the stand alone movie
decoder or update your product using the table below.
<br>
f. VMware Remote Console format string vulnerability
<br>
VMware Remote Console (VMrc) contains a format string vulnerability.
Exploitation of this issue may lead to arbitrary code execution on
the system where VMrc is installed.
<br>
For an attack to be successful, an attacker would need to trick the
VMrc user into opening a malicious Web page or following a malicious
URL. Code execution would be at the privilege level of the user.
<br>
VMrc is present on a system if the VMrc browser plug-in has been
installed. This plug-in is required when using the console feature in
WebAccess. Installation of the plug-in follows after visiting the
console tab in WebAccess and choosing 'Install plug-in'. The plug-
in can only be installed on Internet Explorer and Firefox.
<br>
Under the following two conditions your version of VMrc is likely
to be affected :
<br>
- the VMrc plug-in was obtained from vCenter 4.0 or from ESX 4.0
without patch ESX400-200911223-UG and
- VMrc is installed on a Windows-based system
<br>
The following steps allow you to determine if you have an affected
version of VMrc installed :
<br>
- Locate the VMrc executable vmware-vmrc.exe on your Windows-based
system
- Right click and go to Properties
- Go to the tab 'Versions'
- Click 'File Version' in the 'Item Name' window
- If the 'Value' window shows 'e.x.p build-158248', the version of
VMrc is affected
<br>
Remediation of this issue on Windows-based systems requires the
following steps (Linux-based systems are not affected) :
<br>
- Uninstall affected versions of VMrc from the systems where the
VMrc plug-in has been installed (use the Windows Add/Remove
Programs interface)
- Install vCenter 4.0 Update 1 or install the ESX 4.0 patch
ESX400-200911223-UG
- Login into vCenter 4.0 Update 1 or ESX 4.0 with patch
ESX400-200911223-UG using WebAccess on the system where the VMrc
needs to be re-installed
- Re-install VMrc by going to the console tab in WebAccess.  The
Console tab is selectable after selecting a virtual machine.
<br>
Note: the VMrc plug-in for Firefox on Windows-based operating
systems is no longer compatible after the above remediation steps.
Users are advised to use the Internet Explorer VMrc plug-in.
<br>
VMware would like to thank Alexey Sintsov from Digital Security
Research Group for reporting this issue to us.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2009-3732 to this issue.
<br>

g. Windows-based VMware authd remote denial of service
<br>
A vulnerability in vmware-authd could cause a denial of service
condition on Windows-based hosts.  The denial of service is limited
to a crash of authd.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2009-3707 to this issue.
<br>
h. Potential information leak via hosted networking stack
<br>
A vulnerability in the virtual networking stack of VMware hosted
products could allow host information disclosure.
<br>
A guest operating system could send memory from the host vmware-vmx
process to the virtual network adapter and potentially to the
host's physical Ethernet wire.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2010-1138 to this issue.
<br>
VMware would like to thank Johann MacDonagh for reporting this
issue to us.
<br>
i. Linux-based vmrun format string vulnerability
<br>
A format string vulnerability in vmrun could allow arbitrary code
execution.
<br>
If a vmrun command is issued and processes are listed, code could
be executed in the context of the user listing the processes.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2010-1139 to this issue.
<br>
VMware would like to thank Thomas Toth-Steiner for reporting this
issue to us.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2010-0007.html"

flag = 0

if ESX_check('ESX 3.0.3', 'ESX303-201002203-UG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-200911223-UG'):
    flag += 1;

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
