from wpc.principal import principal
from wpc.process import process
import win32process
import win32ts
import wpc.conf
import ctypes
import win32con

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.c_ulong),
                                 ("cntUsage", ctypes.c_ulong),
                                 ("th32ProcessID", ctypes.c_ulong),
                                 ("th32DefaultHeapID", ctypes.c_ulong),
                                 ("th32ModuleID", ctypes.c_ulong),
                                 ("cntThreads", ctypes.c_ulong),
                                 ("th32ParentProcessID", ctypes.c_ulong),
                                 ("pcPriClassBase", ctypes.c_ulong),
                                 ("dwFlags", ctypes.c_ulong),
                                 ("szExeFile", ctypes.c_char * 260)]

class processes:
    def __init__(self):
        self.processes = []

    def add(self, p):
        self.processes.append(p)

    def get_all(self):
        if self.processes == []:
            pids = win32process.EnumProcesses()
            try:
                proc_infos = win32ts.WTSEnumerateProcesses(wpc.conf.remote_server, 1, 0)
            except:
                proc_infos = []
                pass

            for pid in pids:
                p = process(pid)
                self.add(p)

            for proc_info in proc_infos:
                pid = proc_info[1]
                p = self.find_by_pid(pid)
                if p:  # might fail to find process - race condition
                    p.set_wts_session_id(proc_info[0])
                    p.set_wts_name(proc_info[2])
                    if proc_info[3]:  # sometimes None
                        p.set_wts_sid(principal(proc_info[3]))

            TH32CS_SNAPPROCESS = 0x00000002

            # See http://msdn2.microsoft.com/en-us/library/ms686701.aspx
            CreateToolhelp32Snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot
            Process32First = ctypes.windll.kernel32.Process32First
            Process32Next = ctypes.windll.kernel32.Process32Next
            Thread32First = ctypes.windll.kernel32.Thread32First
            Thread32Next = ctypes.windll.kernel32.Thread32Next
            CloseHandle = ctypes.windll.kernel32.CloseHandle

            hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            pe32 = PROCESSENTRY32()
            pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
            if Process32First(hProcessSnap, ctypes.byref(pe32)) == win32con.FALSE:
                pass
                #print >> sys.stderr, "Failed getting first process."
                #return
            else:
                while True:
                    p = self.find_by_pid(pe32.th32ProcessID)
                    if p:  # might fail to find process - race condition
                        p.set_short_name(pe32.szExeFile)

                    if Process32Next(hProcessSnap, ctypes.byref(pe32)) == win32con.FALSE:
                        break
            CloseHandle(hProcessSnap)

        return self.processes

    def find_by_pid(self, pid):
        for p in self.processes:
            if p.pid == pid:
                return p
        return None