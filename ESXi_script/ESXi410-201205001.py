# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESXi_check
from scanFunction.vuln_check import write_result
import re

name = "VMWare ESXi 4.1.0 Patch Release ESXi410-201205001 Missing (KB2019860)"
cve_id = "N/A"
description = """http://kb.vmware.com/kb/2019860<br>
This patch contains security fixes for ESXi 4.1. For more information, see the KBs for the individual bulletins.  
"""
repair = "https://hostupdate.vmware.com/software/VUM/OFFLINE/release-337-20120501-451487/ESXi410-201205001.zip"

flag = 0
if ESXi_check('ESXi 4.1.0', 702113):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
