# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESXi_check
from scanFunction.vuln_check import write_result
import re

name = "VMWare ESXi 5.0.0 Patch Release ESXi500-201205001 Missing (KB2019857)"
cve_id = "N/A"
description = """http://kb.vmware.com/kb/2019857<br>
This patch release contains security fixes for ESXi. For more information, see the KB articles for the individual bulletins.<br>
For information about the issues fixed with the ESXi-5.0.0-20120504001-standard image profile, see KB 2019863.<br>
For information about the issues fixed with the ESXi-5.0.0-20120504001-no-tools image profile, see KB 2019864.
"""
repair = "https://hostupdate.vmware.com/software/VUM/OFFLINE/release-338-20120501-009635/ESXi500-201205001.zip"

flag = 0
if ESXi_check('ESXi 5.0.0', 702118):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
