# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESXi_check
from scanFunction.vuln_check import write_result
import re

name = "VMWare ESXi 4.1.0 Patch Release update-from-esxi4.1-4.1_update01 Missing (KB1029354)"
cve_id = "N/A"
description = """http://kb.vmware.com/kb/1029354<br>
This bulletin includes all software updates required to install VMware ESXi 4.1 Update 1 on a host. A host will not be considered running ESXi 4.1 Update 1 until it is compliant with this bulletin. For more information, see the KBs for the individual bulletins.
"""
repair = "https://hostupdate.vmware.com/software/VUM/OFFLINE/release-260-20110127-912579/update-from-esxi4.1-4.1_update01.zip"

flag = 0
if ESXi_check('ESXi 4.1.0', 348481):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
