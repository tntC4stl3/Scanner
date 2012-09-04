# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESXi_check
from scanFunction.vuln_check import write_result
import re

name = "VMWare ESXi 5.0.0 Patch Release ESXi500-201207001 Missing (KB2019107)"
cve_id = "N/A"
description = r"""http://kb.vmware.com/kb/2019107<br>
This patch release contains the bug fixes for ESXi. For more information, see the KB articles for the individual bulletins.<br>
For information about the issues fixed with the ESXi-5.0.0-20120704001-standard image profile, see KB 2019113.<br>
For information about the issues fixed with the ESXi-5.0.0-20120704001-no-tools image profile, see KB 2019114.<br>
For information about the issues fixed with the ESXi-5.0.0-20120701001s-standard image profile, see KB 2020574.<br>
For information about the issues fixed with the ESXi-5.0.0-20120701001s-no-tools image profile, see KB 2020575.<br>
"""
repair = "https://hostupdate.vmware.com/software/VUM/OFFLINE/release-346-20120706-638484/ESXi500-201207001.zip"

flag = 0
if ESXi_check('ESXi 5.0.0', 768111):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
