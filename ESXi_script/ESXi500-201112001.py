# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESXi_check
from scanFunction.vuln_check import write_result
import re

name = "VMWare ESXi 5.0.0 Patch Release ESXi500-201112001 Missing (KB2007680)"
cve_id = "N/A"
description = """http://kb.vmware.com/kb/2007680<br>
This patch release contains the bug fixes for ESXi. For more information, see the KB articles for the individual bulletins.<br>
For information about the issues fixed with the ESXi-5.0.0-20111204001-standard image profile, see KB 2009330.<br>
For information about the issues fixed with the ESXi-5.0.0-20111204001-no-tools image profile, see KB 2009334.
"""
repair = "https://hostupdate.vmware.com/software/VUM/OFFLINE/release-325-20111212-924952/ESXi500-201112001.zip"

flag = 0
if ESXi_check('ESXi 5.0.0', 515841):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
