# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESXi_check
from scanFunction.vuln_check import write_result
import re

name = "VMWare ESXi 4.1.0 Patch Release update-from-esxi4.1-4.1_update03 Missing (KB2020373)"
cve_id = "N/A"
description = """http://kb.vmware.com/kb/2020373<br>
This bulletin includes all software updates required to install VMware ESXi 4.1 Update 3 on a host. A host is not considered running ESXi 4.1 Update 3 until it is compliant with this bulletin. For more information, see the KBs for the individual bulletins.
"""
repair = "https://hostupdate.vmware.com/software/VUM/OFFLINE/release-350-20120830-168071/update-from-esxi4.1-4.1_update03.zip"

flag = 0
if ESXi_check('ESXi 4.1.0', 800380):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
