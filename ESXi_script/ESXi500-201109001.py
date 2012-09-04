# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESXi_check
from scanFunction.vuln_check import write_result
import re

name = "VMWare ESXi 5.0.0 Patch Release ESXi500-201109001 Missing (KB2001075)"
cve_id = "N/A"
description = """http://kb.vmware.com/kb/2001075<br>
This patch release contains the bug fixes for ESXi. For more information, see the KB articles for the individual bulletins.
"""
repair = "https://hostupdate.vmware.com/software/VUM/OFFLINE/release-318-20111025-965713/ESXi500-201111001.zip"

flag = 0
if ESXi_check('ESXi 5.0.0', 474610):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
