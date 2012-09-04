# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESXi_check
from scanFunction.vuln_check import write_result
import re

name = "VMWare ESXi 5.0.0 Patch Release update-from-esxi5.0-5.0_update01 Missing (KB2010823)"
cve_id = "N/A"
description = """http://kb.vmware.com/kb/2010823<br>
This patch release contains the bug fixes for ESXi. For more information, see the KB articles for the individual bulletins.<br>
For information about the issues fixed with the ESXi-5.0.0-20120301001s-standard image profile, see KB 2012673.<br>
For information about the issues fixed with the ESXi-5.0.0-20120301001s-no-tools image profile, see KB 2012674.<br>
For information about the issues fixed with the ESXi-5.0.0-20120302001-standard image profile, see KB 2012671.<br>
For information about the issues fixed with the ESXi-5.0.0-20120302001-no-tools image profile, see KB 2012672.
"""
repair = "https://hostupdate.vmware.com/software/VUM/OFFLINE/release-328-20120312-212851/update-from-esxi5.0-5.0_update01.zip"

flag = 0
if ESXi_check('ESXi 5.0.0', 623860):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
