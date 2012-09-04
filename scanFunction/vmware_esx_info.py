# -*- coding:utf-8 -*-
'''
Created on 2012-4-17

@author: Mandj
'''
import paramiko
import re

#global esx_missing_patches, esx_report
#global esx_pkg_l, esx_vib_l, esx_version, newest_bundle;

class esx_pkgs:
    #初始化
    def __init__(self):
        self.NewestBundle = None
        self.esxupdate = None
        self.host_cpu = None
        self.release = None
        self.version = None

    def connect(self, host, username, passwd):
        """通过SSH连接目标ESX Server，获取一些我们关心的信息。"""
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        last = None
        
        #同目标机器建立 SSH 连接
        try:
            self.ssh.connect(host, 22, username, passwd, timeout=4) 
        except:
            print """
Can't connect remote host!!
Maybe the username or password is not correct."""
            return False
        
        #获取平台
       # info = open("esx_info.xml", "w")
       # info.write('<?xml version="1.0" encoding="UTF-8" ?>\n')
       # info.write("<esxInfo>\n")
        stdin, stdout, stderr = self.ssh.exec_command('uname -m')
        cpu = stdout.read()
        if cpu:
            self.host_cpu = cpu.strip()
           # info.write("    <arch>%s</arch>\n" %self.host_cpu )
        
        #获取目标机器 VMware ESX 的发行版本
        stdin, stdout, stderr = self.ssh.exec_command('cat /etc/vmware-release')
        buf = stdout.read();
        if re.search("VMware", buf):
            self.is_esx3 = False
            self.release = buf.strip()
           # info.write("    <release>%s</release>\n" %self.release )
            if re.search("VMware ESX Server 3", buf):
                self.is_esx3 = True
            
            #不支持检测 ESX 3 以前的版本
            if self.is_esx3:
                cmd = "/usr/sbin/esxupdate -l query"
            else:
                cmd = "/usr/sbin/esxupdate query -a" # ESX 4
                
            stdin, stdout, stderr = self.ssh.exec_command(cmd)
            patches = stdout.read()            
            if ((not self.is_esx3) and (not patches or re.search("error: no such option", patches))):
                cmd = "/usr/sbin/esxupdate query"
                stdin, stdout, stderr = self.ssh.exec_command(cmd)
                patches = stdout.read()
            if not patches:
                print "Security checks have been diabled because the command \'" + cmd + \
                      "\' failed to produce any results for some reason."
                return 0
            self.esxupdate = patches.strip()
          #  info.write("    <patches>%s</patch>\n" %self.esxupdate )
            
            lines = patches.split("\n")
            for line in lines:
                v = re.findall('^[ \t]*([^ \t]+)[ \t]', line)
                if v:
                    pkg = v[0]
                    if self.is_esx3:
                        stdin, stdout, stderr = self.ssh.exec_command('/usr/sbin/esxupdate info ' + pkg)
                        v = re.findall('Release Date[ \t]*:[ \t]*(20[0-9][0-9]-[012][0-9]-[0-3][0-9])', stdout.read())
                        if v:
                            date = v[0][0]
                        else :
                            date = None;
                    else :
                        stdin, stdout, stderr = self.ssh.exec_command('/usr/sbin/esxupdate -b ' + pkg + ' info')
                        v = re.findall('[ \t]*(Releasedate|Release Date)[ \t]*-[ \t]*(20[0-9][0-9]-[012][0-9]-[0-3][0-9])', stdout.read())
                        if v:
                            date = v[0][1]
                        else :
                            date = None;
                    if (date) and ((last is None) or date > last):
                        last = date    
            self.NewestBundle = last
          #  info.write("    <NewestBundle>%s</NewestBundle>\n" %self.NewestBundle )
        
        #获取ESX还是ESXi的版本号
        stdin, stdout, stderr = self.ssh.exec_command('/usr/bin/vmware -v')
        buf = stdout.read()
        if buf:
            if re.search("ESXi", buf):
                e = "ESXi"
            elif re.search("ESX", buf):
                e = "ESX"
            v = re.findall("([0-9]\.[0-9])([0-9\.]+)?", buf)
            if v:
                self.version = e + ' ' + v[0][0]
            #    info.write("    <version>%s</version>\n" %self.version )
        self.local_checks_enabled = True
       # info.write("</esxInfo>")
       # info.close()

    def disconnect(self):
        """断开与目标服务器的SSH连接"""
        try:
            self.ssh.close()
        except:
            print "Close SSH error!"

    def get_newestbundle(self):
        """返回补丁包最后的Release Date"""
        return self.NewestBundle

    def get_esxupdate(self):
        """返回已安装补丁列表"""
        return self.esxupdate

    def get_host_cpu(self):
        """返回目标服务器是X86架构还是X64"""
        return self.host_cpu

    def get_release(self):
        """返回发行版本"""
        return self.release

    def get_version(self):
        """返回用于esx_check方法的ESX version"""
        return self.version
    
    def esx_check(self, ver, patch):
        #检查补丁包对应的版本与目标机是否一样。
        if ver != self.version:
            print "The patch is not for this Server."
            return 0
        
        if patch:
            if not self.esxupdate :
                print "The list of installed packages is empty"
                return 1
            elif re.search(patch, self.esxupdate):
                print "The patch has been install."
                return 0
            else:
                print "Can't find the patch"
                return 1

   #     if self.NewestBundle :
   #         v = re.findall("^ESXi?[0-9]+-(20[0-9][0-9])([0-9][0-9])[0-9]+-[A-Z]+$", patch)
   #         date = v[0][0] + '-' + v[0][1] + '-01'
   #        if date <= self.NewestBundle:
   #             print "shi bai le"
   #            return 0
                 
"""
x = esx_pkgs()
x.connect("192.168.172.249", "root", "venus123")
print x.get_host_cpu()
print x.get_release()
print x.get_version()
print x.get_esxupdate()
print x.get_newestbundle()
x.disconnect()
x.esx_check("ESX 4.1", "ESX410-201010409-SG")"""