# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESXi_check
from scanFunction.vuln_check import write_result
import re

name = "VMWare ESXi 4.1.0 Patch Release ESXi410-201107001 Missing (KB2000613)"
cve_id = "N/A"
description = """http://kb.vmware.com/kb/2000613<br>
This patch release contains the bug fixes for ESXi. For more information, see the KB articles for the individual bulletins.
"""
repair = "https://hostupdate.vmware.com/software/VUM/OFFLINE/release-286-20110719-395139/ESXi410-201107001.zip"

flag = 0
if ESXi_check('ESXi 4.1.0', 433742):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
