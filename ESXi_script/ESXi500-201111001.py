# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESXi_check
from scanFunction.vuln_check import write_result
import re

name = "VMWare ESXi 5.0.0 Patch Release ESXi500-201111001 Missing (KB2008017)"
cve_id = "N/A"
description = """http://kb.vmware.com/kb/2008017<br>
This patch release contains the bug fixes for ESXi. For more information, see the KB article of the individual bulletin.
"""
repair = "https://hostupdate.vmware.com/software/VUM/OFFLINE/release-318-20111025-965713/ESXi500-201111001.zip"

flag = 0
if ESXi_check('ESXi 5.0.0', 504890):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
