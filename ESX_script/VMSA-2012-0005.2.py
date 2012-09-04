# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2012-0005.2"
name = "VMSA-2012-0005.2 : VMware vCenter Server, Orchestrator, Update Manager, vShield, vSphere Client, Workstation, Player, ESXi, and ESX address several security issues"
cve_id = "CVE-2010-0405, CVE-2011-3190, CVE-2011-3375, CVE-2011-3389, CVE-2011-3546, CVE-2011-3547, CVE-2011-3554, CVE-2012-0022, CVE-2012-1508, CVE-2012-1510, CVE-2012-1512"
description = """a. VMware Tools Display Driver Privilege Escalation
<br>
The VMware XPDM and WDDM display drivers contain buffer overflow
vulnerabilities and the XPDM display driver does not properly
check for NULL pointers. Exploitation of these issues may lead
to local privilege escalation on Windows-based Guest Operating
Systems.
<br>
VMware would like to thank Tarjei Mandt for reporting theses
issues to us.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2012-1509 (XPDM buffer overrun),
CVE-2012-1510 (WDDM buffer overrun) and CVE-2012-1508 (XPDM null
pointer dereference) to these issues.
<br>
Note: CVE-2012-1509 doesn't affect ESXi and ESX.
<br>
b. vSphere Client internal browser input validation vulnerability
<br>
The vSphere Client has an internal browser that renders html
pages from log file entries. This browser doesn't properly
sanitize input and may run script that is introduced into the
log files. In order for the script to run, the user would need
to open an individual, malicious log file entry. The script
would run with the permissions of the user that runs the vSphere
Client.
<br>
VMware would like to thank Edward Torkington for reporting this
issue to us.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2012-1512 to this issue.
<br>
In order to remediate the issue, the vSphere Client of the
vSphere 5.0 Update 1 release or the vSphere 4.1 Update 2 release
needs to be installed. The vSphere Clients that come with
vSphere 4.0 and vCenter Server 2.5 are not affected.
<br>
c. vCenter Orchestrator Password Disclosure
<br>
The vCenter Orchestrator (vCO) Web Configuration tool reflects
back the vCenter Server password as part of the webpage. This
might allow the logged-in vCO administrator to retrieve the
vCenter Server password.
<br>
VMware would like to thank Alexey Sintsov from Digital Security
Research Group for reporting this issue to us.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2012-1513 to this issue.
<br>
d. vShield Manager Cross-Site Request Forgery vulnerability
<br>
The vShield Manager (vSM) interface has a Cross-Site Request
Forgery vulnerability. If an attacker can convince an
authenticated user to visit a malicious link, the attacker may
force the victim to forward an authenticated request to the
server.
<br>
VMware would like to thank Frans Pehrson of Xxor AB
(www.xxor.se) and Claudio Criscione for independently reporting
this issue to us
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2012-1514 to this issue.
<br>
e. vCenter Update Manager, Oracle (Sun) JRE update 1.6.0_30
<br>
Oracle (Sun) JRE is updated to version 1.6.0_30, which addresses
multiple security issues that existed in earlier releases of
Oracle (Sun) JRE.
<br>
Oracle has documented the CVE identifiers that are addressed in
JRE 1.6.0_29 and JRE 1.6.0_30 in the Oracle Java SE Critical
Patch Update Advisory of October 2011. The References section
provides a link to this advisory.
<br>
f. vCenter Server Apache Tomcat update 6.0.35
<br>
Apache Tomcat has been updated to version 6.0.35 to address
multiple security issues.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2011-3190, CVE-2011-3375, and
CVE-2012-0022 to these issues.
<br>
g. ESXi update to third party component bzip2
<br>
The bzip2 library is updated to version 1.0.6, which resolves a
security issue.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2010-0405 to this issue.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2012-0005.html"

flag = 0
if ESX_check('ESX 4.0', 'ESX400-201110401-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201110201-SG'):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
