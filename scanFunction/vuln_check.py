# -*- coding:utf-8 -*-

from xml.etree import ElementTree
from xml.etree.ElementTree import Element 
import re

info = ElementTree.parse(r"./result/server_info.xml")
global version
global patches
version = info.find('version')

def ESX_check(ver, bulletin):
    
    if ver != version.text:
        print "The patch is not for this Server."
        return 0
    if bulletin:
        patches = info.find('patches')
        if re.search(bulletin, patches.text):
            print "The patch has been install."
            return 0
        else:
            print "Can't find the patch"
            return 1

def ESXi_check(ver, buildnumber):
    
    if ver != version.text:
        print "The patch is not for this Server."
        return 0
    if buildnumber:
        build = info.find('build')
        if buildnumber <= int(build.text):
            print "The patch has been install."
            return 0
        else:
            print "Can't find the patch"
            return 1
"""
def write_result(name, cve_id, description, repair):
    result = open("result.xml", "a")
    result.write("<vuln>\n")
    result.write("  <name>%s</name>\n" % name)
    result.write("  <cve_id>%s</cve_id>\n" % cve_id)
    result.write("  <desc>%s\
  </desc>\n" % description)
    result.write("  <repair>%s</repair>\n" % repair)
    result.write("</vuln>\n")
    result.close()"""

def write_result(name, cveID, desc, repair):
    result = ElementTree.parse("./result/result.xml")
    root = result.getroot()
    
    #子节点vuln
    e_vuln = Element('vuln')
    root.append(e_vuln)
    #vuln的子节点name
    e_name = Element('name')
    e_name.text = name
    e_vuln.append(e_name)
    #vuln的子节点cveID
    e_cveID = Element('cveID')
    e_cveID.text = cveID
    e_vuln.append(e_cveID)
    #vuln的子节点desc
    e_desc = Element('desc')
    e_desc.text = desc
    e_vuln.append(e_desc)
    #vuln的子节点repaire
    e_repair = Element('repair')
    e_repair.text = repair
    e_vuln.append(e_repair)

    ElementTree.ElementTree(root).write("./result/result.xml", encoding="UTF-8")
