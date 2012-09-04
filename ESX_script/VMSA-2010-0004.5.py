# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2010-0004.5"
name = "VMSA-2010-0004.5 : ESX Service Console and vMA third party updates"
cve_id = "CVE-2008-3916, CVE-2008-4316, CVE-2008-4552, CVE-2009-0115, CVE-2009-0590, CVE-2009-1189, CVE-2009-1377, CVE-2009-1378, CVE-2009-1379, CVE-2009-1386, CVE-2009-1387, CVE-2009-2695, CVE-2009-2849, CVE-2009-2904, CVE-2009-2905, CVE-2009-2908, CVE-2009-3228, CVE-2009-3286, CVE-2009-3547, CVE-2009-3560, CVE-2009-3563, CVE-2009-3612, CVE-2009-3613, CVE-2009-3620, CVE-2009-3621, CVE-2009-3720, CVE-2009-3726, CVE-2009-4022"
description = """a. vMA and Service Console update for newt to 0.52.2-12.el5_4.1
<br>
Newt is a programming library for color text mode, widget based
user interfaces. Newt can be used to add stacked windows, entry
widgets, checkboxes, radio buttons, labels, plain text fields,
scrollbars, etc., to text mode user interfaces.
<br>
A heap-based buffer overflow flaw was found in the way newt
processes content that is to be displayed in a text dialog box.
A local attacker could issue a specially-crafted text dialog box
display request (direct or via a custom application), leading to a
denial of service (application crash) or, potentially, arbitrary
code execution with the privileges of the user running the
application using the newt library.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2009-2905 to this issue.
<br>
b. vMA and Service Console update for vMA package nfs-utils to
1.0.9-42.el5
<br>
The nfs-utils package provides a daemon for the kernel NFS server
and related tools.
<br>
It was discovered that nfs-utils did not use tcp_wrappers
correctly.  Certain hosts access rules defined in '/etc/hosts.allow'
and '/etc/hosts.deny' may not have been honored, possibly allowing
remote attackers to bypass intended access restrictions.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2008-4552 to this issue.
<br>
c. vMA and Service Console package glib2 updated to 2.12.3-4.el5_3.1
<br>
GLib is the low-level core library that forms the basis for
projects such as GTK+ and GNOME. It provides data structure
handling for C, portability wrappers, and interfaces for such
runtime functionality as an event loop, threads, dynamic loading,
and an object system.
<br>
Multiple integer overflows in glib/gbase64.c in GLib before 2.20
allow context-dependent attackers to execute arbitrary code via a
long string that is converted either from or to a base64
representation.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2008-4316 to this issue.
<br>
d. vMA and Service Console update for openssl to 0.9.8e-12.el5
<br>
SSL is a toolkit implementing SSL v2/v3 and TLS protocols with full-
strength cryptography world-wide.
<br>
Multiple denial of service flaws were discovered in OpenSSL's DTLS
implementation. A remote attacker could use these flaws to cause a
DTLS server to use excessive amounts of memory, or crash on an
invalid memory access or NULL pointer dereference.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the names CVE-2009-1377, CVE-2009-1378,
CVE-2009-1379, CVE-2009-1386, CVE-2009-1387 to these issues.
<br>
An input validation flaw was found in the handling of the BMPString
and UniversalString ASN1 string types in OpenSSL's
ASN1_STRING_print_ex() function. An attacker could use this flaw to
create a specially-crafted X.509 certificate that could cause
applications using the affected function to crash when printing
certificate contents.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2009-0590 to this issue.
<br>
e. vMA and Service Console package bind updated to 9.3.6-4.P1.el5_4.1
<br>
It was discovered that BIND was incorrectly caching responses
without performing proper DNSSEC validation, when those responses
were received during the resolution of a recursive client query
that requested DNSSEC records but indicated that checking should be
disabled. A remote attacker could use this flaw to bypass the DNSSEC
validation check and perform a cache poisoning attack if the target
BIND server was receiving such client queries.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2009-4022 to this issue.
<br>
f. vMA and Service Console package expat updated to 1.95.8-8.3.el5_4.2.
<br>
Two buffer over-read flaws were found in the way Expat handled
malformed UTF-8 sequences when processing XML files. A specially-
crafted XML file could cause applications using Expat to fail while
parsing the file.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the names CVE-2009-3560 and CVE-2009-3720 to these
issues.
<br>
g. vMA and Service Console package openssh update to 4.3p2-36.el5_4.2
<br>
A Red Hat specific patch used in the openssh packages as shipped in
Red Hat Enterprise Linux 5.4 (RHSA-2009:1287) loosened certain
ownership requirements for directories used as arguments for the
ChrootDirectory configuration options. A malicious user that also
has or previously had non-chroot shell access to a system could
possibly use this flaw to escalate their privileges and run
commands as any system user.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2009-2904 to this issue.
<br>
h. vMA and Service Console package ntp updated to
ntp-4.2.2p1-9.el5_4.1.i386.rpm
<br>
A flaw was discovered in the way ntpd handled certain malformed NTP
packets. ntpd logged information about all such packets and replied
with an NTP packet that was treated as malformed when received by
another ntpd. A remote attacker could use this flaw to create an NTP
packet reply loop between two ntpd servers through a malformed packet
with a spoofed source IP address and port, causing ntpd on those
servers to use excessive amounts of CPU time and fill disk space with
log messages.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2009-3563 to this issue.   
<br>
i. vMA update for package kernel to 2.6.18-164.9.1.el5
<br>
Updated vMA package kernel addresses the security issues listed
below.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2009-2849 to the security issue fixed in
kernel 2.6.18-128.2.1
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2009-2695, CVE-2009-2908, CVE-2009-3228,
CVE-2009-3286, CVE-2009-3547, CVE-2009-3613 to the security issues
fixed in kernel 2.6.18-128.6.1
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2009-3612, CVE-2009-3620, CVE-2009-3621,
CVE-2009-3726 to the security issues fixed in kernel
2.6.18-128.9.1
<br>
j. vMA 4.0 updates for the packages kpartx, libvolume-id,
device-mapper-multipath, fipscheck, dbus, dbus-libs, and ed
<br>
kpartx updated to 0.4.7-23.el5_3.4, libvolume-id updated to
095-14.20.el5 device-mapper-multipath package updated to
0.4.7-23.el5_3.4, fipscheck updated to 1.0.3-1.el5, dbus
updated to 1.1.2-12.el5, dbus-libs updated to 1.1.2-12.el5,
and ed package updated to 0.2-39.el5_2.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the names CVE-2008-3916, CVE-2009-1189 and
CVE-2009-0115 to these issues.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2010-0004.html"

flag = 0

if ESX_check('ESX 3.5.0', 'ESX350-201006407-SG'):
    flag += 1;
if ESX_check('ESX 3.5.0', 'ESX350-201008406-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201002404-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201002406-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201002407-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201005403-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201005404-SG'):
    flag += 1;

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
