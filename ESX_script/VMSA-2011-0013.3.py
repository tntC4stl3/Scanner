# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2011-0013.3"
name = "VMSA-2011-0013.3 : VMware third party component updates for VMware vCenter Server, vCenter Update Manager, ESXi and ESX"
cve_id = "CVE-2008-7270, CVE-2010-1321, CVE-2010-2054, CVE-2010-3170, CVE-2010-3173, CVE-2010-3541, CVE-2010-3548, CVE-2010-3549, CVE-2010-3550, CVE-2010-3551, CVE-2010-3552, CVE-2010-3553, CVE-2010-3554, CVE-2010-3555, CVE-2010-3556, CVE-2010-3557, CVE-2010-3558, CVE-2010-3559, CVE-2010-3560, CVE-2010-3561, CVE-2010-3562, CVE-2010-3563, CVE-2010-3565, CVE-2010-3566, CVE-2010-3567, CVE-2010-3568, CVE-2010-3569, CVE-2010-3570, CVE-2010-3571, CVE-2010-3572, CVE-2010-3573, CVE-2010-3574, CVE-2010-4180, CVE-2010-4422, CVE-2010-4447, CVE-2010-4448, CVE-2010-4450, CVE-2010-4451, CVE-2010-4452, CVE-2010-4454, CVE-2010-4462, CVE-2010-4463, CVE-2010-4465, CVE-2010-4466, CVE-2010-4467, CVE-2010-4468, CVE-2010-4469, CVE-2010-4470, CVE-2010-4471, CVE-2010-4472, CVE-2010-4473, CVE-2010-4474, CVE-2010-4475, CVE-2010-4476, CVE-2011-0002, CVE-2011-0802, CVE-2011-0814, CVE-2011-0815, CVE-2011-0862, CVE-2011-0864, CVE-2011-0865, CVE-2011-0867, CVE-2011-0871, CVE-2011-0873"
description = """a. ESX third party update for Service Console openssl RPM
<br>
The Service Console openssl RPM is updated to
openssl-0.9.8e.12.el5_5.7 resolving two security issues.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2008-7270 and CVE-2010-4180 to these
issues.
<br>
b. ESX third party update for Service Console libuser RPM
<br>
The Service Console libuser RPM is updated to version
0.54.7-2.1.el5_5.2 to resolve a security issue.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2011-0002 to this issue.
<br>
c. ESX third party update for Service Console nss and nspr RPMs
<br>
The Service Console Network Security Services (NSS) and Netscape
Portable Runtime (NSPR) libraries are updated to nspr-4.8.6-1
and nss-3.12.8-4 resolving multiple security issues.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2010-3170 and CVE-2010-3173 to these
issues.
<br>
d. vCenter Server and ESX, Oracle (Sun) JRE update 1.6.0_24
<br>
Oracle (Sun) JRE is updated to version 1.6.0_24, which addresses
multiple security issues that existed in earlier releases of
Oracle (Sun) JRE.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the following names to the security issues fixed in
JRE 1.6.0_24: CVE-2010-4422, CVE-2010-4447, CVE-2010-4448,
CVE-2010-4450, CVE-2010-4451, CVE-2010-4452, CVE-2010-4454,
CVE-2010-4462, CVE-2010-4463, CVE-2010-4465, CVE-2010-4466,
CVE-2010-4467, CVE-2010-4468, CVE-2010-4469, CVE-2010-4470,
CVE-2010-4471, CVE-2010-4472, CVE-2010-4473, CVE-2010-4474,
CVE-2010-4475 and CVE-2010-4476.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the following names to the security issues fixed in
JRE 1.6.0_22: CVE-2010-1321, CVE-2010-3541, CVE-2010-3548,
CVE-2010-3549, CVE-2010-3550, CVE-2010-3551, CVE-2010-3552,
CVE-2010-3553, CVE-2010-3554, CVE-2010-3555, CVE-2010-3556,
CVE-2010-3557, CVE-2010-3558, CVE-2010-3559, CVE-2010-3560,
CVE-2010-3561, CVE-2010-3562, CVE-2010-3563, CVE-2010-3565,
CVE-2010-3566, CVE-2010-3567, CVE-2010-3568, CVE-2010-3569,
CVE-2010-3570, CVE-2010-3571, CVE-2010-3572, CVE-2010-3573 and
CVE-2010-3574.
<br>
e. vCenter Update Manager Oracle (Sun) JRE update 1.5.0_30
<br>
Oracle (Sun) JRE is updated to version 1.5.0_30, which addresses
multiple security issues that existed in earlier releases of
Oracle (Sun) JRE.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the following names to the security issues fixed in
Oracle (Sun) JRE 1.5.0_30: CVE-2011-0862, CVE-2011-0873,
CVE-2011-0815, CVE-2011-0864, CVE-2011-0802, CVE-2011-0814,
CVE-2011-0871, CVE-2011-0867 and CVE-2011-0865.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the following names to the security issues fixed in
Oracle (Sun) JRE 1.5.0_28: CVE-2010-4447, CVE-2010-4448,
CVE-2010-4450, CVE-2010-4454, CVE-2010-4462, CVE-2010-4465,
CVE-2010-4466, CVE-2010-4468, CVE-2010-4469, CVE-2010-4473,
CVE-2010-4475, CVE-2010-4476.
<br>
f. Integer overflow in VMware third party component sfcb
<br>
This release resolves an integer overflow issue present in the
third party library SFCB when the httpMaxContentLength has been
changed from its default value to 0 in in /etc/sfcb/sfcb.cfg.
The integer overflow could allow remote attackers to cause a
denial of service (heap memory corruption) or possibly execute
arbitrary code via a large integer in the Content-Length HTTP
header.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2010-2054 to this issue.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2011-0013.html"

flag = 0
if ESX_check('ESX 4.0', 'ESX400-201111201-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201203401-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201203406-SG'):
    flag += 1;
if ESX_check('ESX 4.1', 'ESX410-201110201-SG'):
    flag += 1;
if ESX_check('ESX 4.1', 'ESX410-201110204-SG'):
    flag += 1;
if ESX_check('ESX 4.1', 'ESX410-201110206-SG'):
    flag += 1;
if ESX_check('ESX 4.1', 'ESX410-201110214-SG'):
    flag += 1;
if ESX_check('ESX 4.1', 'ESX410-201110201-SG'):
    flag += 1;

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
