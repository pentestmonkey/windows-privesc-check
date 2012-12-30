from wpc.file import file as File
from wpc.sd import sd
from wpc.token import token
import win32api
import win32con
import win32security
import wpc.utils
import ctypes

OpenThread = ctypes.windll.kernel32.OpenThread
#OpenThreadToken = ctypes.windll.advapi32.OpenThreadToken

class thread:
    def __init__(self, tid):
        self.tid = tid
        self.th = None
        self.tth = None
        self.token = None
        self.sd = None
        self.parent_process = None

    def get_tid(self):
        return self.tid

    def set_parent_process(self, p):
        self.parent_process = p

    def get_parent_process(self):
        return self.parent_process

    def get_sd(self):
        #print "[D] get_sd passed th: %s" % self.get_th()
        if not self.sd:
            try:
             secdesc = win32security.GetSecurityInfo(self.get_th(), win32security.SE_KERNEL_OBJECT, win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION | win32security.GROUP_SECURITY_INFORMATION)
             #print "[D] secdesc: %s" % secdesc
             self.sd = sd('thread', secdesc)
            except:
                pass
        #print "[D] get_sd returning: %s" % self.sd
        return self.sd

    def get_th(self):
        if not self.th:
            try:
                # THREAD_ALL_ACCESS needed to get security descriptor
                self.th = OpenThread(win32con.MAXIMUM_ALLOWED, False, self.get_tid())
                #print "Openthread with THREAD_ALL_ACCESS: Success"
            except:
                try:
                    # THREAD_VM_READ is required to list modules (DLLs, EXE)
                    self.th = OpenThread(win32con.THREAD_VM_READ | win32con.THREAD_QUERY_INFORMATION, False, self.get_tid())
                    #print "Openthread with VM_READ and THREAD_QUERY_INFORMATION: Success"
                except:
                    #print "Openthread with VM_READ and THREAD_QUERY_INFORMATION: Failed"
                    try:
                        # We can still get some info without THREAD_VM_READ
                        self.th = OpenThread(win32con.THREAD_QUERY_INFORMATION, False, self.get_tid())
                        #print "Openthread with THREAD_QUERY_INFORMATION: Success"
                    except:
                        #print "Openthread with THREAD_QUERY_INFORMATION: Failed"
                        try:
                            # If we have to resort to using THREAD_QUERY_LIMITED_INFORMATION, the thread is protected.
                            # There's no point trying THREAD_VM_READ
                            # Ignore pydev warning.  We define this at runtime because win32con is out of date.
                            self.th = OpenThread(win32con.THREAD_QUERY_LIMITED_INFORMATION, False, self.get_tid())
                            #print "Openthread with THREAD_QUERY_LIMITED_INFORMATION: Success"
                        except:
                            #print "Openthread with THREAD_QUERY_LIMITED_INFORMATION: Failed"
                            self.th = None
#        self.th = win32api.PyHANDLE(self.th)
        #print "[D] get_th: %s" % self.th
        return self.th

    def get_tth(self):
        if not self.tth:
            import sys
            import pywintypes
            try:
                self.tth = win32security.OpenThreadToken(self.get_th(), win32con.MAXIMUM_ALLOWED, True)
            except pywintypes.error as e:
                #print sys.exc_info()[0]
                #print "xxx"
                #print "[E] %s: %s" % (e[1], e[2])
                pass
            #    try:
            #        self.tth = win32security.OpenThreadToken(self.get_th(), win32con.TOKEN_READ, True)
            #    except:
            #        try:
            #            self.tth = win32security.OpenThreadToken(self.get_th(), win32con.TOKEN_QUERY, True)
                    #print "OpenthreadToken with TOKEN_QUERY: Failed"
            #        except:
            #            pass
#        print "[D] TTH: %s" % self.tth
        return self.tth

    def get_token(self):
        if not self.token:
            if self.get_tth():
                self.token = token(self.get_tth())
        #print "thread get_token: %s" % self.token
        return self.token

    def as_text(self):
        t = ''
        t += "-------------------------------------------------\n"
        t += "TID:            " + str(self.get_tid()) + "\n"
        t += "\nThread Security Descriptor:\n"
        if self.get_sd():
            t += self.get_sd().as_text()

        t += "\nThread Access Token:\n"
        tok = self.get_token()
        if tok:
            t += "Thread token found:\n"
            t += tok.as_text()
        else:
            t += "[None - thread not impersonating]\n"

        return t
