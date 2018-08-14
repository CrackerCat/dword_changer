from idaapi import *
try:
    from PyQt5.QtCore import *
    from PyQt5.QtGui import *
    from PyQt5.QtWidgets import *
except:
    from PySide.QtCore import *
    from PySide.QtGui import *
    from PySide import QtGui

from functools import partial

string = []
dword_addr = []
blacklist_string = ["!", "#", "^", "*", "-", "+", "=", ";", "'", "\"", "\\", "|", "{", "}", "/", "<", ">", ","]

def get_string(addr):
    out = ""
    while True:
        if Byte(addr) != 0:
            out += chr(Byte(addr))
        else:
            break
        addr += 1
    for i in blacklist_string:
        out = out.replace(i, "_")
    return out

class dword_changer(PluginForm):

    def Using_rename(self):
        self.Start = self.StartAddress.text()
        self.End = self.EndAddress.text()
        self.rename_variable(Start, End)

    def rename_variable(self):
        start = int(self.StartAddress.text(), 16)
        end = int(self.EndAddress.text(), 16)
        while start <= end:
            if "offset" in GetOpnd(start, 0):
                variable = GetOpnd(start, 0).split(" ")[1]
                addr = get_name_ea(start,variable)
                string.append(get_string(addr))

            elif "offset" in GetOpnd(start, 1):
                variable = GetOpnd(start, 1).split(" ")[1]
                addr = get_name_ea(start,variable)
                string.append(get_string(addr))

            elif "dword_" in GetOpnd(start, 0) and GetMnem(start) == "mov":
                dword_addr.append(GetOpnd(start, 0))

            elif "dword_" in GetOpnd(start, 1) and GetMnem(start) == "mov":
                dword_addr.append(GetOpnd(start, 1))

            start = idc.NextHead(start)

        for i in range(len(string)):
            print dword_addr[i], string[i] + "_" + dword_addr[i]
            idc.MakeName(int(dword_addr[i].replace("dword_",""),16), string[i] + "_" + dword_addr[i])

    def OnCreate(self, form):
        try:
            self.parent = self.FormToPyQtWidget(form)
        except:
            self.parent = self.FormToPySideWidget(form)

        self.label1 = QLabel("Start Address : ")
        self.label2 = QLabel("End Address : ")
        self.StartAddress = QLineEdit()
        self.EndAddress = QLineEdit()
        self.PushButton1 = QPushButton("Change")
        self.PushButton1.clicked.connect(self.rename_variable)

        self.layout = QVBoxLayout()
        GL1 = QGridLayout()
        GL1.addWidget(self.label1, 0, 0)
        GL1.addWidget(self.StartAddress, 0, 1)
        GL1.addWidget(self.label2, 0, 2)
        GL1.addWidget(self.EndAddress, 0, 3)
        self.layout.addLayout(GL1)

        GL2 = QGridLayout()
        GL2.addWidget(self.PushButton1, 0, 0)
        self.layout.addLayout(GL2)
        self.parent.setLayout(self.layout)

    def OnClose(self, form):
        pass

plg = dword_changer()
plg.Show("dword_changer")
'''
class Plugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "dword_changer"
    help = "help"
    wanted_name = "dword_changer"
    wanted_hotkey = "Ctrl+Shift+D"

    def init(self):
        idaapi.msg("[*] dword_changer Plugin\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        plg = dword_changer()
        plg.Show("dword_changer")

    def term(self):
        pass

def PLUGIN_ENTRY():
    return Plugin()
'''