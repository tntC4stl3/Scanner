# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from scanFunction.vuln_check import ESX_check
from scanFunction.vuln_check import write_result
import re

VMSA = "VMSA-2010-0009.2"
name = "VMSA-2010-0009.2 : ESXi ntp and ESX Service Console third party updates"
cve_id = "CVE-2006-6304, CVE-2007-4567, CVE-2009-0590, CVE-2009-1377, CVE-2009-1378, CVE-2009-1379, CVE-2009-1384, CVE-2009-1386, CVE-2009-1387, CVE-2009-2409, CVE-2009-2695, CVE-2009-2908, CVE-2009-2910, CVE-2009-3080, CVE-2009-3228, CVE-2009-3286, CVE-2009-3547, CVE-2009-3556, CVE-2009-3563, CVE-2009-3612, CVE-2009-3613, CVE-2009-3620, CVE-2009-3621, CVE-2009-3726, CVE-2009-3736, CVE-2009-3889, CVE-2009-3939, CVE-2009-4020, CVE-2009-4021, CVE-2009-4138, CVE-2009-4141, CVE-2009-4212, CVE-2009-4272, CVE-2009-4355, CVE-2009-4536, CVE-2009-4537, CVE-2009-4538, CVE-2010-0001, CVE-2010-0097, CVE-2010-0290, CVE-2010-0382, CVE-2010-0426, CVE-2010-0427"
description = """a. Service Console update for COS kernel
<br>
Updated COS package 'kernel' addresses the security issues that are
fixed through versions 2.6.18-164.11.1.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2009-2695, CVE-2009-2908, CVE-2009-3228,
CVE-2009-3286, CVE-2009-3547, CVE-2009-3613 to the security issues
fixed in kernel 2.6.18-164.6.1
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2009-3612, CVE-2009-3620, CVE-2009-3621,
CVE-2009-3726 to the security issues fixed in kernel 2.6.18-164.9.1.
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2007-4567, CVE-2009-4536, CVE-2009-4537,
CVE-2009-4538 to the security issues fixed in kernel 2.6.18-164.10.1
<br>
The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2006-6304, CVE-2009-2910, CVE-2009-3080,
CVE-2009-3556, CVE-2009-3889, CVE-2009-3939, CVE-2009-4020,
CVE-2009-4021, CVE-2009-4138, CVE-2009-4141, and CVE-2009-4272 to
the security issues fixed in kernel 2.6.18-164.11.1.
<br>
b. ESXi userworld update for ntp
<br>
The Network Time Protocol (NTP) is used to synchronize the time of
a computer client or server to another server or reference time
source.
<br>
A vulnerability in ntpd could allow a remote attacker to cause a
denial of service (CPU and bandwidth consumption) by using
MODE_PRIVATE to send a spoofed (1) request or (2) response packet
that triggers a continuous exchange of MODE_PRIVATE error responses
between two NTP daemons.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2009-3563 to this issue.
<br>
c. Service Console package openssl updated to 0.9.8e-12.el5_4.1
<br>
OpenSSL is a toolkit implementing SSL v2/v3 and TLS protocols with
full-strength cryptography world-wide.
<br>
A memory leak in the zlib could allow a remote attacker to cause a
denial of service (memory consumption) via vectors that trigger
incorrect calls to the CRYPTO_cleanup_all_ex_data function.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2009-4355 to this issue.
<br>
A vulnerability was discovered which may allow remote attackers to
spoof certificates by using MD2 design flaws to generate a hash
collision in less than brute-force time. NOTE: the scope of this
issue is currently limited because the amount of computation
required is still large.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2009-2409 to this issue.
<br>
This update also includes security fixes that were first addressed
in version openssl-0.9.8e-12.el5.i386.rpm.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the names CVE-2009-0590, CVE-2009-1377, CVE-2009-1378,
CVE-2009-1379, CVE-2009-1386 and CVE-2009-1387 to these issues.
<br>
d. Service Console update for krb5 to 1.6.1-36.el5_4.1 and pam_krb5 to
2.2.14-15.
<br>
Kerberos is a network authentication protocol. It is designed to
provide strong authentication for client/server applications by
using secret-key cryptography.
<br>
Multiple integer underflows in the AES and RC4 functionality in the
crypto library could allow remote attackers to cause a denial of
service (daemon crash) or possibly execute arbitrary code by
providing ciphertext with a length that is too short to be valid.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2009-4212 to this issue.
<br>
The service console package for pam_krb5 is updated to version
pam_krb5-2.2.14-15. This update fixes a flaw found in pam_krb5. In
some non-default configurations (specifically, where pam_krb5 would
be the first module to prompt for a password), a remote attacker
could use this flaw to recognize valid usernames, which would aid a
dictionary-based password guess attack.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2009-1384 to this issue.
<br>
e. Service Console package bind updated to 9.3.6-4.P1.el5_4.2
<br>
BIND (Berkeley Internet Name Daemon) is by far the most widely used
Domain Name System (DNS) software on the Internet.
<br>
A vulnerability was discovered which could allow remote attacker to
add the Authenticated Data (AD) flag to a forged NXDOMAIN response
for an existing domain.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2010-0097 to this issue.
<br>
A vulnerability was discovered which could allow remote attackers
to conduct DNS cache poisoning attacks by receiving a recursive
client query and sending a response that contains CNAME or DNAME
records, which do not have the intended validation before caching.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2010-0290 to this issue.
<br>
A vulnerability was found in the way that bind handles out-of-
bailiwick data accompanying a secure response without re-fetching
from the original source, which could allow remote attackers to
have an unspecified impact via a crafted response.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2010-0382 to this issue.
<br>
NOTE: ESX does not use the BIND name service daemon by default.
<br>
f. Service Console package gcc updated to 3.2.3-60
<br>
The GNU Compiler Collection includes front ends for C, C++,
Objective-C, Fortran, Java, and Ada, as well as libraries for these
languages
<br>
GNU Libtool's ltdl.c attempts to open .la library files in the
current working directory.  This could allow a local user to gain
privileges via a Trojan horse file.  The GNU C Compiler collection
(gcc) provided in ESX contains a statically linked version of the
vulnerable code, and is being replaced.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2009-3736 to this issue.
<br>
g. Service Console package gzip update to 1.3.3-15.rhel3
<br>
gzip is a software application used for file compression
<br>
An integer underflow in gzip's unlzw function on 64-bit platforms
may allow a remote attacker to trigger an array index error
leading to a denial of service (application crash) or possibly
execute arbitrary code via a crafted LZW compressed file.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2010-0001 to this issue.
<br>
h. Service Console package sudo updated to 1.6.9p17-6.el5_4
<br>
Sudo (su 'do') allows a system administrator to delegate authority
to give certain users (or groups of users) the ability to run some
(or all) commands as root or another user while providing an audit
trail of the commands and their arguments.
<br>
When a pseudo-command is enabled, sudo permits a match between the
name of the pseudo-command and the name of an executable file in an
arbitrary directory, which allows local users to gain privileges
via a crafted executable file.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2010-0426 to this issue.
<br>
When the runas_default option is used, sudo does not properly set
group memberships, which allows local users to gain privileges via
a sudo command.
<br>
The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2010-0427 to this issue.
"""
repair = "http://www.vmware.com/security/advisories/VMSA-2010-0009.html"

flag = 0

if ESX_check('ESX 3.5.0', 'ESX350-201006405-SG'):
    flag += 1;
if ESX_check('ESX 3.5.0', 'ESX350-201006406-SG'):
    flag += 1;
if ESX_check('ESX 3.5.0', 'ESX350-201006408-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201005401-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201005405-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201005406-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201005407-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201005408-SG'):
    flag += 1;
if ESX_check('ESX 4.0', 'ESX400-201005409-SG'):
    flag += 1;

if flag:
    write_result(name, cve_id, description, repair)
   # return "Patches in %s is missing!!\n" % VMSA
