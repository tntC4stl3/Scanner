# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESXi_check
from scanFunction.vuln_check import write_result
import re

name = "VMWare ESXi 5.0.0 Patch Release ESXi500-201204001 Missing (KB2015460)"
cve_id = "N/A"
description = """http://kb.vmware.com/kb/2015460<br>
This patch release contains security fixes for ESXi. For more information, see the KB articles for the individual bulletins.<br>
For information about the issues fixed with the ESXi-5.0.0-20120404001-standard image profile, see KB 2015650.<br>
For information about the issues fixed with the ESXi-5.0.0-20120404001-no-tools image profile, see KB 2015655.
"""
repair = "https://hostupdate.vmware.com/software/VUM/OFFLINE/release-331-20120408-206167/ESXi500-201204001.zip"

flag = 0
if ESXi_check('ESXi 5.0.0', 653509):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
