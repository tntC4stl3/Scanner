# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2010-0003.1"
name = "VMSA-2010-0003.1 : ESX Service Console update for net-snmp"
cve_id = "CVE-2008-4309, CVE-2009-1887"
description = """a. Service Console package net-snmp updated
<br>
This patch updates the service console package for net-snmp,
net-snmp-utils, and net-snmp-libs to version
net-snmp-5.0.9-2.30E.28. This net-snmp update fixes a divide-by-
zero flaw in the snmpd daemon. A remote attacker could issue a
specially crafted GETBULK request that could cause the snmpd daemon
to fail.
<br>
This vulnerability was introduced by an incorrect fix for
CVE-2008-4309.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org) has
assigned the name CVE-2009-1887 to this issue.
<br>
Note: After installing the previous patch for net-snmp
(ESX350-200901409-SG), running the snmpbulkwalk command with the
parameter -CnX results in no output, and the snmpd daemon stops.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2010-0003.html"

flag = 0

if ESX_check('ESX 3.0.3', 'ESX303-201002202-SG'):
    flag += 1
if ESX_check('ESX 3.5.0', 'ESX350-201002401-SG'):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
