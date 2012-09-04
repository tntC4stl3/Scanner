# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESXi_check
from scanFunction.vuln_check import write_result
import re

name = "VMWare ESXi 4.1.0 Patch Release ESXi410-201206001 Missing (KB2019243)"
cve_id = "N/A"
description = """http://kb.vmware.com/kb/2019243<br>
This patch contains security fixes for ESXi 4.1. For more information, see the KB for the individual bulletin. 
"""
repair = "https://hostupdate.vmware.com/software/VUM/OFFLINE/release-343-20120605-042482/ESXi410-201206001.zip"

flag = 0
if ESXi_check('ESXi 4.1.0', 721871):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
