from wpc.file import file as File
from wpc.regkey import regkey
from wpc.sd import sd
import os
import re
import win32con
import win32security
import win32service
import wpc.conf


class service:
    def __init__(self, scm, short_name):
        self.scm = scm
        self.name = short_name
        self.sh = None  # service handle
        self.sd = None  # sd for service
        self.description = None
        self.type = None
        self.sh_read_control = None
        self.service_info = None
        self.service_config_failure_actions = None
        self.service_sid_type = None
        self.long_description = None
        self.exe_path = None  # e.g. C:\Windows\system32\svchost.exe -k netsvcs
        self.exe_path_clean = None  # e.g. C:\Windows\system32\svchost.exe
        self.exe_file = None  # wpc.file for self.exe_path_clean
        self.status = None  # started, stopped
        self.startup_type = None  # auto, auto (delayed), manual, disabled
        self.run_as = None  # wpc.user object for e.g. localsystem
        self.interactive = None  # 0 or 1
        self.sh_query_status = None
        self.sh_query_config = None
        self.reg_key = None

    # We need different rights from the OpenService call for the different API calls we need to make
    # See http://msdn.microsoft.com/en-us/library/ms685981(v=vs.85).aspx
    # READ_CONTROL to call QueryServiceObjectSecurity
    # SERVICE_QUERY_STATUS for QueryServiceStatus
    # SERVICE_QUERY_CONFIG for QueryServiceConfig and QueryServiceConfig2
    #
    # We try to get a different handle for each.  That way we only ask for what we need and should
    # get the maximum info about each service.

    def get_sh_query_config(self):
        if not self.sh_query_config:    
            try:
                self.sh_query_config = win32service.OpenService(self.get_scm(), self.get_name(), win32service.SERVICE_QUERY_CONFIG)

            except:
                print "Service Perms: Unknown (Access Denied)"

        return self.sh_query_config

    def get_sh_query_status(self):
        if not self.sh_query_status:
            try:
                self.sh_query_status = win32service.OpenService(self.get_scm(), self.get_name(), win32service.SERVICE_QUERY_STATUS)
            except:
                pass
        return self.sh_query_status

    def get_sh_read_control(self):
        if not self.sh_read_control:
            try:
                self.sh_read_control = win32service.OpenService(self.get_scm(), self.get_name(), win32con.READ_CONTROL)
            except:
                pass
        return self.sh_read_control

    def get_status(self):
        if not self.status:
            try:
                s = win32service.QueryServiceStatus(self.get_sh_query_status())
                self.status = s[1]
                if self.status == 1:
                    self.status = "STOPPED"
                elif self.status == 4:
                    self.status = "STARTED"
            except:
                pass
        return self.status

    def get_scm(self):
        return self.scm

    def get_sd(self):
        if not self.sd:
            # Need a handle with generic_read
            try:
                secdesc = win32service.QueryServiceObjectSecurity(self.get_sh_read_control(), win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
                self.sd = sd('service', secdesc)
            except:
                print "ERROR: OpenService failed for '%s' (%s)" % (self.get_description(), self.get_name())

        return self.sd

    def get_name(self):
        return self.name

    def get_exe_file(self):
        if not self.exe_file:
            filename = self.get_exe_path_clean()
            if filename:  # might be None
                self.exe_file = File(filename)
            else:
                self.exe_file = None
        return self.exe_file

    def get_exe_path_clean(self):
        if not self.exe_path_clean:
            self.exe_path_clean = None
            binary_dirty = self.get_exe_path()

            # remove quotes and leading white space
            m = re.search('^[\s]*?"([^"]+)"', binary_dirty)
            if m and os.path.exists(m.group(1)):
                self.exe_path_clean = m.group(1)
                return self.exe_path_clean
            else:
                if m:
                    binary_dirty = m.group(1)

            # Paths for drivers are written in an odd way, so we regex them
            re1 = re.compile(r'^\\systemroot', re.IGNORECASE)
            binary_dirty = re1.sub(os.getenv('SystemRoot'), binary_dirty)
            re2 = re.compile(r'^system32\\', re.IGNORECASE)
            binary_dirty = re2.sub(os.getenv('SystemRoot') + r'\\system32\\', binary_dirty)
            re2 = re.compile(r'^\\\?\?\\', re.IGNORECASE)
            binary_dirty = re2.sub('', binary_dirty)
            binary_dirty = binary_dirty.replace("/", "\\")  # c:/foo/bar -> c:\foo\bar

            if os.path.exists(binary_dirty):
                self.exe_path_clean = binary_dirty
                return self.exe_path_clean

            chunks = binary_dirty.split(" ")
            candidate = ""
            for chunk in chunks:
                if candidate:
                    candidate = candidate + " "
                candidate = candidate + chunk

                if os.path.exists(candidate) and os.path.isfile(candidate):
                    self.exe_path_clean = candidate
                    break

                if os.path.exists(candidate + ".exe") and os.path.isfile(candidate + ".exe"):
                    self.exe_path_clean = candidate + ".exe"
                    break

                if wpc.conf.on64bitwindows:
                    candidate2 = candidate.replace("system32", "syswow64")
                    if os.path.exists(candidate2) and os.path.isfile(candidate2):
                        self.exe_path_clean = candidate2
                        break

                    if os.path.exists(candidate2 + ".exe") and os.path.isfile(candidate2 + ".exe"):
                        self.exe_path_clean = candidate2 + ".exe"
                        break
        return self.exe_path_clean

    def get_exe_path(self):
        if not self.exe_path:
            self.exe_path = self.get_service_info(3)
        return self.exe_path

    def get_run_as(self):
        if not self.run_as:
            self.run_as = self.get_service_info(7)
        return self.run_as

    def set_interactive(self, n):
        self.interactive = n

    # service or driver?
    def get_type(self):
        if not self.type:
            self.type = self.get_service_info(0)
            if not self.type == '[unknown]':
                if self.type & 0x100:
                    self.type = self.type - 0x100
                    self.set_interactive(1)
                else:
                    self.set_interactive(0)

                if self.type == 1:
                    self.type = "KERNEL_DRIVER"
                elif self.type == 2:
                    self.type = "FILE_SYSTEM_DRIVER"
                elif self.type == 32:
                    self.type = "WIN32_SHARE_PROCESS"
                elif self.type == 16:
                    self.type = "WIN32_OWN_PROCESS"
        return self.type

    def get_startup_type(self):
        if not self.startup_type:
            self.startup_type = self.get_service_info(1)
            if self.startup_type == 2:
                self.startup_type = "AUTO_START"
            elif self.startup_type == 0:
                self.startup_type = "BOOT_START"
            elif self.startup_type == 3:
                self.startup_type = "DEMAND_START"
            elif self.startup_type == 4:
                self.startup_type = "DISABLED"
            elif self.startup_type == 1:
                self.startup_type = "SYSTEM_START"
        return self.startup_type

    def get_description(self):
        if not self.description:
            self.description = self.get_service_info(8)
        return self.description

    def get_service_info(self, n):
        if not self.service_info:
            try:
                self.service_info = win32service.QueryServiceConfig(self.get_sh_query_config())
            except:
                pass

        if self.service_info:
            return self.service_info[n]
        else:
            return "[unknown]"

    def get_service_config_failure_actions(self):
        if not self.service_config_failure_actions:
            try:
                self.service_config_failure_actions = win32service.QueryServiceConfig2(self.get_sh_query_config(), win32service.SERVICE_CONFIG_FAILURE_ACTIONS)
            except:
                pass
            if not self.service_config_failure_actions:
                self.service_config_failure_actions = ""
        return self.service_config_failure_actions

    def get_service_sid_type(self):
        if not self.service_sid_type:
            try:
                self.service_sid_type = win32service.QueryServiceConfig2(self.get_sh_query_config(), win32service.SERVICE_CONFIG_SERVICE_SID_INFO)
                if self.service_sid_type == 0:
                    self.service_sid_type = "SERVICE_SID_TYPE_NONE"
                if self.service_sid_type == 1:
                    self.service_sid_type = "SERVICE_SID_TYPE_RESTRICTED"
                if self.service_sid_type == 2:
                    self.service_sid_type = "SERVICE_SID_TYPE_UNRESTRICTED"
            except:
                pass
        return self.service_sid_type

    def get_long_description(self):
        if not self.long_description:
            try:
                self.long_description = win32service.QueryServiceConfig2(self.get_sh_query_config(), win32service.SERVICE_CONFIG_DESCRIPTION)
            except:
                pass
            if not self.long_description:
                self.long_description = ""
        return self.long_description

    def as_text(self):
        return self._as_text(0)

    def untrusted_as_text(self):
        return self._as_text(1)

    def _as_text(self, flag):
        t = ""
        t += "---------------------------------------\n"
        t += "Service:        " + self.get_name() + "\n"
        t += "Description:    " + self.get_description() + "\n"
        t += "Type:           " + str(self.get_type()) + "\n"
        t += "Status:         " + str(self.get_status()) + "\n"
        t += "Startup:        " + str(self.get_startup_type()) + "\n"
        t += "Long Desc:      " + self.removeNonAscii(self.get_long_description()) + "\n"  # in case of stupid chars in desc
        t += "Binary:         " + self.get_exe_path() + "\n"
        if self.get_exe_path_clean():
            t += "Binary (clean): " + self.get_exe_path_clean() + "\n"
        else:
            t += "Binary (clean): [Missing Binary]\n"
        t += "Run as:         " + self.get_run_as() + "\n"
        t += "Svc Sid Type:   " + str(self.get_service_sid_type()) + "\n"
        t += "Failure Actions:%s\n" % self.get_service_config_failure_actions()
        t += "\n"
        t += "Service Security Descriptor:\n"
        if self.get_sd():
            if flag:
                t += self.get_sd().untrusted_as_text() + "\n"
            else:
                t += self.get_sd().as_text() + "\n"
        else:
            t += "[unknown]\n"
        t += "\n"
        t += "Security Descriptor for Executable:" + "\n"
        if self.get_exe_file():
            if flag:
                t += self.get_exe_file().get_sd().untrusted_as_text() + "\n"
            else:
                t += self.get_exe_file().get_sd().as_text() + "\n"
        else:
            t += "[unknown]\n"

        t += "Security Descriptor for Registry Key:" + "\n"
        if self.get_reg_key():
            if flag:
                t += self.get_reg_key().get_sd().untrusted_as_text()
            else:
                t += self.get_reg_key().as_text()
        else:
            t += "[unknown]\n"

        t += "\n"
        return t
        return t

    def get_reg_key(self):
        if not self.reg_key:
            self.reg_key = regkey("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\" + self.get_name())
        return self.reg_key

    def removeNonAscii(self, s): 
        return "".join(i for i in s if ord(i) < 128)