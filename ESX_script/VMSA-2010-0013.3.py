# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2010-0013"
name = "VMSA-2010-0013 : VMware ESX third party updates for Service Console"
cve_id = "CVE-2005-4268, CVE-2007-4476, CVE-2008-5302, CVE-2008-5303, CVE-2010-0624, CVE-2010-1168, CVE-2010-1321, CVE-2010-1447, CVE-2010-2063"
description = """a. Service Console update for cpio
<br>
The service console package cpio is updated to version 2.5-6.RHEL3
for ESX 3.x versions and updated to version 2.6-23.el5_4.1 for
ESX 4.x versions.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2005-4268 and CVE-2010-0624 to the issues
addressed in the update for ESX 3.x and the names CVE-2007-4476 and
CVE-2010-0624 to the issues addressed in the update for ESX 4.x.
<br>
b. Service Console update for tar
<br>
The service console package tar is updated to version
1.13.25-16.RHEL3 for ESX 3.x versions and updated to version
1.15.1-23.0.1.el5_4.2 for ESX 4.x versions.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2010-0624 to the issue addressed in the
update for ESX 3.x and the names CVE-2007-4476 and CVE-2010-0624
to the issues addressed in the update for ESX 4.x.
<br>
c. Service Console update for samba
<br>
The service console packages for samba are updated to version
samba-3.0.9-1.3E.17vmw, samba-client-3.0.9-1.3E.17vmw and
samba-common-3.0.9-1.3E.17vmw.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2010-2063 to the issue addressed in this
update.
<br>
Note :
The issue mentioned above is present in the Samba server (smbd) and
is not present in the Samba client or Samba common packages.
<br>
To determine if your system has Samba server installed do a
'rpm -q samba`.
<br>
The following lists when the Samba server is installed on the ESX
service console :
<br>
- ESX 4.0, ESX 4.1
The Samba server is not present on ESX 4.0 and ESX 4.1.
<br>
- ESX 3.5
The Samba server is present if an earlier patch for Samba has been
installed.
<br>
- ESX 3.0.3
The Samba server is present if ESX 3.0.3 was upgraded from an
earlier version of ESX 3 and a Samba patch was installed on that
version.
<br>
The Samba server is not needed to operate the service console and
can be be disabled without loss of functionality to the service
console.
<br>
d. Service Console update for krb5
<br>
The service console package krb5 is updated to version 1.2.7-72
for ESX 3.x versions and to version 1.6.1-36.el5_5.4 for ESX 4.x
versions.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2010-1321 to the issue addressed in
these updates.
<br>
e. Service Console update for perl
<br>
The service console package perl is updated to version
5.8.0-101.EL3 for ESX 3.x versions and version 5.8.8-32.el5_5.1
for ESX 4.x versions.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2010-1168 and CVE-2010-1447 to the issues
addressed in the update for ESX 3.x and the names CVE-2008-5302,
CVE-2008-5303, CVE-2010-1168, and CVE-2010-1447 to the issues
addressed in the update for ESX 4.x.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2010-0013.html"

flag = 0

if ESX_check('ESX 3.0.3', 'ESX303-201102402-SG'):
    flag += 1;
if ESX_check('ESX 3.5.0', 'ESX350-201008405-SG'):
    flag += 1;
if ESX_check('ESX 3.5.0', 'ESX350-201008407-SG'):
    flag += 1;
if ESX_check('ESX 3.5.0', 'ESX350-201008410-SG'):
    flag += 1;
if ESX_check('ESX 3.5.0', 'ESX350-201008411-SG'):
    flag += 1;
if ESX_check('ESX 3.5.0', 'ESX350-201008412-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201009402-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201009403-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201009406-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201009411-SG'):
    flag += 1;
if ESX_check('ESX 4.1', 'ESX410-201010409-SG'):
    flag += 1;
if ESX_check('ESX 4.1', 'ESX410-201010412-SG'):
    flag += 1;
if ESX_check('ESX 4.1', 'ESX410-201010413-SG'):
    flag += 1;

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
