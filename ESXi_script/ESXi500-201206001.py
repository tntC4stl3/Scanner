# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESXi_check
from scanFunction.vuln_check import write_result
import re

name = "VMWare ESXi 5.0.0 Patch Release ESXi500-201206001 Missing (KB2021031)"
cve_id = "N/A"
description = r"""This patch release contains security fixes for ESXi. For more information, see the KB article for the individual bulletin.<br>
For information about the issues fixed with the ESXi-5.0.0-20120604001-standard image profile, see KB 2021035.<br>
For information about the issues fixed with the ESXi-5.0.0-20120604001-no-tools image profile, see KB 2021036.<br>
"""
repair = "https://hostupdate.vmware.com/software/VUM/OFFLINE/release-341-20120605-165537/ESXi500-201206001.zip"

flag = 0
if ESXi_check('ESXi 5.0.0', 721882):
    flag += 1

if flag:
    write_result(name, cve_id, description, repair)
