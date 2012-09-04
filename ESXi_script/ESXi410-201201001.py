# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESXi_check
from scanFunction.vuln_check import write_result
import re

name = "VMWare ESXi 4.1.0 Patch Release ESXi410-201201001 Missing (KB2009137)"
cve_id = "N/A"
description = """http://kb.vmware.com/kb/2009137<br>
This bulletin includes all software updates required to install VMware ESXi 4.1 Patch 04 on a host. A host is not considered running ESXi 4.1 Patch 04 until it is compliant with this bulletin. For more information, see the KBs for the individual bulletins.
"""
repair = "https://hostupdate.vmware.com/software/VUM/OFFLINE/release-327-20120123-039410/ESXi410-201201001.zip"

flag = 0
if ESXi_check('ESXi 4.1.0', 582267):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
