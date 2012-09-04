# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESXi_check
from scanFunction.vuln_check import write_result
import re

name = "VMWare ESXi 4.1.0 Patch Release ESXi410-201204001 Missing (KB2013058)"
cve_id = "N/A"
description = """http://kb.vmware.com/kb/2013058<br>
This bulletin includes all software updates required to install VMware ESXi 4.1 Patch 05 on a host. A host is not considered running ESXi 4.1 Patch 05 until it is compliant with this bulletin. For more information, see the KBs for the individual bulletins.  
"""
repair = "https://hostupdate.vmware.com/software/VUM/OFFLINE/release-333-20120419-954937/ESXi410-201204001.zip"

flag = 0
if ESXi_check('ESXi 4.1.0', 659051):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
