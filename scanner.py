# -*- coding:utf-8 -*-
import sys
sys.path.append('.')

from Tkinter import *
from pysphere import VIServer
import re, os
from scanFunction.vmware_esx_info import *

class MyApp:
    def __init__(self, parent):
        self.myScanner = parent
       # self.myScanner.geometry('800x600')
        self.myScanner.title('ESX/ESXi Server Vulnerability Scanner')
        self.myContainer = Frame(parent)
        self.myContainer.pack()
        
        # 提示
        self.tip = Label(self.myContainer, text = "提示:\n\
请输入IP、先获取服务器版本。如果是ESX Server，请继续输入用户名，\n\
密码然后开始扫描；如果是ESXi Server，无需用户名密码，直接扫描。\n\
扫描完成后，打开index.html查看结果。", bg = 'green')
        self.tip.grid(row = 0, column = 0, columnspan = 3)
        
        # IP
        self.ip_label = Label(self.myContainer, text="IP:")
        self.ip_label.grid(row = 1, column = 0, sticky = E+W)
        self.ip = Entry(self.myContainer, text="")
        self.ip.grid(row = 1, column = 1, sticky = E+W)

        # 先检查是ESX还是ESXi
        self.getVersion_button = Button(self.myContainer, text="获取服务器版本", fg="black", command = self.serverVersion) #lose command
        self.getVersion_button.grid(row = 1, column = 2, sticky = W+E)
        
        # Server版本
        self.version_label = Label(self.myContainer, text="服务器版本:")
        self.version_label.grid(row = 2, column = 0, sticky = E+W)
        self.version_text = Text(self.myContainer, width = 35, height = 1)
        self.version_text.grid(row = 2, column = 1, columnspan = 2, sticky = E+W)
        
        # 用户名
        self.user_label = Label(self.myContainer, text="用户名:")
        self.user_label.grid(row = 3, column = 0, sticky = E+W)
        self.user = Entry(self.myContainer, text="")
        self.user.grid(row = 3, column = 1, sticky = E+W)
        
        # 密码
        self.passwd_label = Label(self.myContainer, text="密码:")
        self.passwd_label.grid(row = 4, column = 0, sticky = E+W)
        self.passwd = Entry(self.myContainer, text="")
        self.passwd.grid(row = 4, column = 1, sticky = E+W)
        self.passwd['show'] = '*'
        
        # 检查是否有漏洞
        self.vulnCheck_button = Button(self.myContainer, text="扫描", fg="black", command = self.vulnCheck) #lose command
        self.vulnCheck_button.grid(row = 3, column = 2, rowspan = 2, sticky = W+E)
        
        """# 运行状况
        self.status_label = Label(self.myContainer, text="运行状况:")
        self.status_label.grid(row = 5, column = 0, sticky = E+W)
        
        # 运行状态
        self.status = Text(self.myContainer, width = 48)
        self.status.grid(row = 6, column = 0, columnspan = 3)"""
        
    def serverVersion(self):
        self.server = VIServer()
        try:
            self.server.connect_no_auth(self.ip.get())
            self.serverFullname = self.server.get_server_fullname()
            self.server.disconnect()
            self.version_text.insert('end', self.serverFullname)
        except:
            print "Maybe the remote host is not a ESX/ESXi Server."
    
    def vulnCheck(self):
        #重置result.xml
        result = open("result/result.xml", "w")
        result.write("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n")
        result.write("<result>\n")
        result.write("</result>\n")
        result.close()
        if re.search('ESXi', self.serverFullname):
            self.version = re.search('\d\.\d\.\d', self.serverFullname)
            self.buildnumber = re.search('\d{6}', self.serverFullname)
            
            # 填写Server信息
            info = open("result/server_info.xml", "w")
            info.write('<?xml version="1.0" encoding="UTF-8" ?>\n')
            info.write("<serverInfo>\n")
            info.write("    <release>%s</release>\n" %self.serverFullname)
            info.write("    <version>ESXi %s</version>\n" %self.version.group())
            info.write("    <build>%s</build>\n" %self.buildnumber.group())
            info.write("</serverInfo>")
            
            info.close()
            
            #获取ESXi扫描脚本
            vmsas = os.listdir('ESXi_script')
            for vmsa in vmsas:
                if vmsa != '__init__.py':
                    cmd = "python ESXi_script/%s" % vmsa.strip()
                    os.system(cmd)
                   # self.status.insert(1.0, "%s complete!\n" % vmsa.strip())
                   # self.status.insert(END, "%s complete!\n" % vmsa.strip())
        else:
            x = esx_pkgs()
            #重置esx_info.xml
            info = open("result/server_info.xml", "w")
            if x.connect(self.ip.get(), self.user.get(), self.passwd.get()) != False:
               # 连接目标服务器成功
               # self.status.insert(1.0, "Connect remote ESX Server success!!\n")
               # self.status.insert('end', "Connect remote ESX Server success!!\n")
               # self.status.get(INSERT)
                
                info.write('<?xml version="1.0" encoding="UTF-8" ?>\n')
                info.write("<serverInfo>\n")
                info.write("    <arch>%s</arch>\n" %x.get_host_cpu())
                info.write("    <release>%s</release>\n" %self.serverFullname)
                info.write("    <version>%s</version>\n" %x.get_version())
                info.write("    <patches>%s</patches>\n" %x.get_esxupdate())
                info.write("    <NewestBundle>%s</NewestBundle>\n" %x.get_newestbundle())
                info.write("</serverInfo>")
            else: # 连接目标服务器失败
               # self.status.insert(1.0, "Can't connect remote ESX server!!\nMaybe the username or password is not correct.\n")
               # self.status.insert('end', "Can't connect remote ESX server!!\nMaybe the username or password is not correct.\n")
                return False
    
            info.close()
            x.disconnect()
            
            #获取ESX扫描脚本
            vmsas = os.listdir('ESX_script')
            for vmsa in vmsas:
                if vmsa != '__init__.py':
                    cmd = "python ESX_script/%s" % vmsa.strip()
                    os.system(cmd)
                   # self.status.insert(1.0, "%s complete!\n" % vmsa.strip())
                   # self.status.insert(END, "%s complete!\n" % vmsa.strip())
            
root = Tk()
scanner = MyApp(root)
root.mainloop()
