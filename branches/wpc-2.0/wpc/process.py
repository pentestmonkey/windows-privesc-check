from wpc.file import file as File
from wpc.sd import sd
from wpc.token import token
import win32api
import win32con
import win32process
import win32security
import wpc.utils


class process:
    def __init__(self, pid):
        self.pid = pid
        self.ph = None
        self.pth = None
        self.exe = None
        self.exe_path_dirty = None
        self.exe_path_clean = None
        self.wow64 = None
        self.mhs = None
        self.dlls = []
        self.wts_name = None
        self.wts_session_id = None
        self.wts_sid = None
        self.token = None
        self.short_name = "[none]"
        self.sd = None

    def get_pid(self):
        return self.pid

    def set_wts_name(self, wts_name):
        self.wts_name = wts_name

    def set_short_name(self, n):
        self.short_name = n

    def get_short_name(self):
        return self.short_name

    def get_wts_session_id(self):
        return self.wts_session_id

    def set_wts_session_id(self, wts_session_id):
        self.wts_session_id = wts_session_id

    def get_wts_sid(self):
        return self.wts_sid

    def set_wts_sid(self, wts_sid):
        self.wts_sid = wts_sid

    def get_wts_name(self):
        return self.wts_name

    def get_sd(self):
        if not self.sd:
            try:
                secdesc = win32security.GetSecurityInfo(self.get_ph(), win32security.SE_KERNEL_OBJECT, win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION | win32security.GROUP_SECURITY_INFORMATION)
                self.sd = sd('process', secdesc)
            except:
                pass
        return self.sd

    def get_mhs(self):
        if not self.mhs:
            if self.get_ph():
                try:
                    mhs = win32process.EnumProcessModules(self.get_ph())
                    self.mhs = list(mhs)
                except:
                    pass
        return self.mhs

    def get_dlls(self):
        if self.dlls == []:
            if self.get_mhs():
                for mh in self.get_mhs():
                    dll = win32process.GetModuleFileNameEx(self.get_ph(), mh)
                    #print dll
                    self.dlls.append(File(dll))
                    #dump_perms(dll, 'file', {'brief': 1})
        return self.dlls

    def get_exe_path_clean(self):
        if not self.exe_path_clean:
            self.exe_path_clean = wpc.utils.get_exe_path_clean(self.get_exe_path_dirty())
            if not self.exe_path_clean:
                self.exe_path_clean = self.get_exe_path_dirty()
        return self.exe_path_clean

    def get_exe_path_dirty(self):
        if not self.exe_path_dirty:
            if self.get_mhs():
                self.exe_path_dirty = win32process.GetModuleFileNameEx(self.get_ph(), self.get_mhs().pop(0))
        return self.exe_path_dirty

    def get_exe(self):
        if not self.exe:
            if self.get_exe_path_dirty():
                self.exe = File(self.get_exe_path_clean())
        return self.exe

    def get_ph(self):
        if not self.ph:
            try:
                # PROCESS_ALL_ACCESS needed to get security descriptor
                self.ph = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, self.get_pid())
                #print "OpenProcess with PROCESS_ALL_ACCESS: Success"
            except:
                try:
                    # PROCESS_VM_READ is required to list modules (DLLs, EXE)
                    self.ph = win32api.OpenProcess(win32con.PROCESS_VM_READ | win32con.PROCESS_QUERY_INFORMATION, False, self.get_pid())
                    #print "OpenProcess with VM_READ and PROCESS_QUERY_INFORMATION: Success"
                except:
                    #print "OpenProcess with VM_READ and PROCESS_QUERY_INFORMATION: Failed"
                    try:
                        # We can still get some info without PROCESS_VM_READ
                        self.ph = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, self.get_pid())
                        #print "OpenProcess with PROCESS_QUERY_INFORMATION: Success"
                    except:
                        #print "OpenProcess with PROCESS_QUERY_INFORMATION: Failed"
                        try:
                            # If we have to resort to using PROCESS_QUERY_LIMITED_INFORMATION, the process is protected.
                            # There's no point trying PROCESS_VM_READ
                            # Ignore pydev warning.  We define this at runtime because win32con is out of date.
                            self.ph = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, self.get_pid())
                            #print "OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION: Success"
                        except:
                            #print "OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION: Failed"
                            self.ph = None
        return self.ph

    def get_pth(self):
        if not self.pth:
            try:
                self.pth = win32security.OpenProcessToken(self.get_ph(), win32con.TOKEN_ALL_ACCESS)
            except:
                try:
                    self.pth = win32security.OpenProcessToken(self.get_ph(), win32con.TOKEN_READ)
                except:
                    try:
                        self.pth = win32security.OpenProcessToken(self.get_ph(), win32con.TOKEN_QUERY)
                    #print "OpenProcessToken with TOKEN_QUERY: Failed"
                    except:
                        pass
        return self.pth

    def is_wow64(self):
        if not self.wow64 and self.get_ph():
            self.wow64 = win32process.IsWow64Process(self.get_ph())
        return self.wow64

    def get_token(self):
        if not self.token:
            if self.get_pth():
                self.token = token(self.get_pth())
        return self.token

    def as_text(self):
        t = ''
        t += "-------------------------------------------------\n"
        t += "PID:            " + str(self.get_pid()) + "\n"
        t += "Short Name:     " + str(self.get_short_name()) + "\n"
        t += "WTS Name:       " + str(self.get_wts_name()) + "\n"
        t += "WTS Session ID: " + str(self.get_wts_session_id()) + "\n"
        if self.get_wts_sid():
            t += "WTS Sid:        " + str(self.get_wts_sid().get_fq_name()) + "\n"
        else:
            t += "WTS Sid:        None\n"
        if self.get_ph():
            t += "Is WOW64:       " + str(self.is_wow64()) + "\n"
            if self.get_exe():
                t += "Exe:            " + str(self.get_exe().get_name()) + "\n"
            else:
                t += "Exe:        [unknown]\n"
            t += "Modules:\n"
            for dll in self.get_dlls():
                t += "\t\t" + dll.get_name() + "\n"

        t += "\nProcess Security Descriptor:\n"
        if self.get_sd():
            t += self.get_sd().as_text()

        t += "\nProcess Access Token:\n"
        if self.get_token():
            t += self.get_token().as_text()
        else:
            t += "[unknown]"
        return t
