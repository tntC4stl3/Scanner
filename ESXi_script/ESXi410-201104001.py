# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESXi_check
from scanFunction.vuln_check import write_result
import re

name = "VMWare ESXi 4.1.0 Patch Release ESXi410-201104001 Missing (KB1035111)"
cve_id = "N/A"
description = """http://kb.vmware.com/kb/1035111<br>
This patch release contains the bug fixes for ESXi. For more information, see the KB articles for the individual bulletins.
"""
repair = "https://hostupdate.vmware.com/software/VUM/OFFLINE/release-276-20110420-682352/ESXi410-201104001.zip"

flag = 0
if ESXi_check('ESXi 4.1.0', 381591):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
