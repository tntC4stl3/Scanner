# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2011-0003.2"
name = "VMSA-2011-0003.2 : Third party component updates for VMware vCenter Server, vCenter Update Manager, ESXi and ESX"
cve_id = "CVE-2008-0085, CVE-2008-0086, CVE-2008-0106, CVE-2008-0107, CVE-2008-3825, CVE-2008-5416, CVE-2009-1384, CVE-2009-2693, CVE-2009-2901, CVE-2009-2902, CVE-2009-3548, CVE-2009-3555, CVE-2009-4308, CVE-2010-0003, CVE-2010-0007, CVE-2010-0008, CVE-2010-0082, CVE-2010-0084, CVE-2010-0085, CVE-2010-0087, CVE-2010-0088, CVE-2010-0089, CVE-2010-0090, CVE-2010-0091, CVE-2010-0092, CVE-2010-0093, CVE-2010-0094, CVE-2010-0095, CVE-2010-0291, CVE-2010-0307, CVE-2010-0410, CVE-2010-0415, CVE-2010-0433, CVE-2010-0437, CVE-2010-0622, CVE-2010-0730, CVE-2010-0734, CVE-2010-0740, CVE-2010-0837, CVE-2010-0838, CVE-2010-0839, CVE-2010-0840, CVE-2010-0841, CVE-2010-0842, CVE-2010-0843, CVE-2010-0844, CVE-2010-0845, CVE-2010-0846, CVE-2010-0847, CVE-2010-0848, CVE-2010-0849, CVE-2010-0850, CVE-2010-0886, CVE-2010-1084, CVE-2010-1085, CVE-2010-1086, CVE-2010-1087, CVE-2010-1088, CVE-2010-1157, CVE-2010-1173, CVE-2010-1187, CVE-2010-1321, CVE-2010-1436, CVE-2010-1437, CVE-2010-1641, CVE-2010-2066, CVE-2010-2070, CVE-2010-2226, CVE-2010-2227, CVE-2010-2240, CVE-2010-2248, CVE-2010-2521, CVE-2010-2524, CVE-2010-2928, CVE-2010-2939, CVE-2010-3081, CVE-2010-3541, CVE-2010-3548, CVE-2010-3549, CVE-2010-3550, CVE-2010-3551, CVE-2010-3553, CVE-2010-3554, CVE-2010-3556, CVE-2010-3557, CVE-2010-3559, CVE-2010-3561, CVE-2010-3562, CVE-2010-3565, CVE-2010-3566, CVE-2010-3567, CVE-2010-3568, CVE-2010-3569, CVE-2010-3571, CVE-2010-3572, CVE-2010-3573, CVE-2010-3574, CVE-2010-3864"
description = """a. vCenter Server and vCenter Update Manager update Microsoft
SQL Server 2005 Express Edition to Service Pack 3
<br>
Microsoft SQL Server 2005 Express Edition (SQL Express)
distributed with vCenter Server 4.1 Update 1 and vCenter Update
Manager 4.1 Update 1 is upgraded from  SQL Express Service Pack 2
to SQL Express Service Pack 3, to address multiple security
issues that exist in the earlier releases of Microsoft SQL Express.
<br>
Customers using other database solutions need not update for
these issues.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2008-5416, CVE-2008-0085, CVE-2008-0086,
CVE-2008-0107 and CVE-2008-0106 to the issues addressed in MS SQL
Express Service Pack 3.
<br>
b. vCenter Apache Tomcat Management Application Credential Disclosure
<br>
The Apache Tomcat Manager application configuration file contains
logon credentials that can be read by unprivileged local users.
<br>
The issue is resolved by removing the Manager application in
vCenter 4.1 Update 1.
<br>
If vCenter 4.1 is updated to vCenter 4.1 Update 1 the logon
credentials are not present in the configuration file after the
update.
<br>
VMware would like to thank Claudio Criscione of Secure Networking
for reporting this issue to us.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2010-2928 to this issue.
<br>
c. vCenter Server and ESX, Oracle (Sun) JRE is updated to version
1.6.0_21
<br>
Oracle (Sun) JRE update to version 1.6.0_21, which addresses
multiple security issues that existed in earlier releases of
Oracle (Sun) JRE.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the following names to the security issues fixed in
Oracle (Sun) JRE 1.6.0_19: CVE-2009-3555, CVE-2010-0082,
CVE-2010-0084, CVE-2010-0085, CVE-2010-0087, CVE-2010-0088,
CVE-2010-0089, CVE-2010-0090, CVE-2010-0091, CVE-2010-0092,
CVE-2010-0093, CVE-2010-0094, CVE-2010-0095, CVE-2010-0837,
CVE-2010-0838, CVE-2010-0839, CVE-2010-0840, CVE-2010-0841,
CVE-2010-0842, CVE-2010-0843, CVE-2010-0844, CVE-2010-0845,
CVE-2010-0846, CVE-2010-0847, CVE-2010-0848, CVE-2010-0849,
CVE-2010-0850.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the following name to the security issue fixed in
Oracle (Sun) JRE 1.6.0_20: CVE-2010-0886.
<br>
d. vCenter Update Manager Oracle (Sun) JRE is updated to version
1.5.0_26
<br>
Oracle (Sun) JRE update to version 1.5.0_26, which addresses
multiple security issues that existed in earlier releases of
Oracle (Sun) JRE.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the following names to the security issues fixed in
Oracle (Sun) JRE 1.5.0_26: CVE-2010-3556, CVE-2010-3566,
CVE-2010-3567, CVE-2010-3550, CVE-2010-3561, CVE-2010-3573,
CVE-2010-3565,CVE-2010-3568, CVE-2010-3569,  CVE-2009-3555,
CVE-2010-1321, CVE-2010-3548, CVE-2010-3551, CVE-2010-3562,
CVE-2010-3571, CVE-2010-3554, CVE-2010-3559, CVE-2010-3572,
CVE-2010-3553, CVE-2010-3549, CVE-2010-3557, CVE-2010-3541,
CVE-2010-3574.
<br>
e. vCenter Server and ESX Apache Tomcat updated to version 6.0.28
<br>
Apache Tomcat updated to version 6.0.28, which addresses multiple
security issues that existed in earlier releases of Apache Tomcat
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the following names to the security issues fixed in
Apache Tomcat 6.0.24: CVE-2009-2693, CVE-2009-2901, CVE-2009-2902,i
and CVE-2009-3548.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the following names to the security issues fixed in
Apache Tomcat 6.0.28: CVE-2010-2227, CVE-2010-1157.
<br>
f. vCenter Server third party component OpenSSL updated to version
0.9.8n
<br>
The version of the OpenSSL library in vCenter Server is updated to
0.9.8n.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2010-0740 and CVE-2010-0433 to the
issues addressed in this version of OpenSSL.
<br>
g. ESX third party component OpenSSL updated to version 0.9.8p
<br>
The version of the ESX OpenSSL library is updated to 0.9.8p.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2010-3864 and CVE-2010-2939 to the
issues addressed in this update.
<br>
h. ESXi third party component cURL updated
<br>
The version of cURL library in ESXi is updated.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2010-0734 to the issues addressed in
this update.
<br>
i. ESX third party component pam_krb5 updated
<br>
The version of pam_krb5 library is updated.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2008-3825 and CVE-2009-1384 to the
issues addressed in the update.
<br>
j. ESX third party update for Service Console kernel
<br>
The Service Console kernel is updated to include kernel version
2.6.18-194.11.1.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2010-1084, CVE-2010-2066, CVE-2010-2070,
CVE-2010-2226, CVE-2010-2248, CVE-2010-2521, CVE-2010-2524,
CVE-2010-0008, CVE-2010-0415, CVE-2010-0437, CVE-2009-4308,
CVE-2010-0003, CVE-2010-0007, CVE-2010-0307, CVE-2010-1086,
CVE-2010-0410, CVE-2010-0730, CVE-2010-1085, CVE-2010-0291,
CVE-2010-0622, CVE-2010-1087, CVE-2010-1173, CVE-2010-1437,
CVE-2010-1088, CVE-2010-1187, CVE-2010-1436, CVE-2010-1641, and
CVE-2010-3081 to the issues addressed in the update.
<br>
Notes :
- The update also addresses the 64-bit compatibility mode
stack pointer underflow issue identified by CVE-2010-3081. This
issue was patched in an ESX 4.1 patch prior to the release of
ESX 4.1 Update 1 and in a previous ESX 4.0 patch release.
- The update also addresses CVE-2010-2240 for ESX 4.0.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2011-0003.html"

flag = 0
if ESX_check('ESX 4.0', 'ESX400-201103401-SG'):
    flag += 1
if ESX_check('ESX 4.0', 'ESX400-201103403-SG'):
    flag += 1
if ESX_check('ESX 4.1', 'ESX410-201101201-SG'):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
