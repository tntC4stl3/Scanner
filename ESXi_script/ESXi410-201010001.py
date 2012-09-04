# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESXi_check
from scanFunction.vuln_check import write_result
import re

name = "VMWare ESXi 4.1.0 Patch Release ESXi410-201010001 Missing (KB1027753)"
cve_id = "N/A"
description = """http://kb.vmware.com/kb/1027753<br>
This patch release contains the bug fixes for ESXi. For more information, see the KB articles for the individual bulletins.
"""
repair = "https://hostupdate.vmware.com/software/VUM/OFFLINE/release-251-20101108-239087/ESXi410-201010001.zip"

flag = 0
if ESXi_check('ESXi 4.1.0', 320092):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
