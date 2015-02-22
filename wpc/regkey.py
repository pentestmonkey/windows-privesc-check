from wpc.report.issueAcl import issueAcl
from wpc.sd import sd
import ntsecuritycon
import win32api
import win32con
import win32security
import wpc.conf


# regkeys or directories
class regkey:
    def __init__(self, key_string, **kwargs):
        # print "[D] Created regkey obj for " + name
        self.sd = None
        self.keyh = None
        self.hive = None
        self.path = None
        self.set_name(key_string)
        self.parent_key = None
        self.view = None
        if 'view' in kwargs.keys():
            self.view = kwargs['view']   # 64 or 32 

    def set_name(self, key_string):
        parts = key_string.split("\\")
        if parts[0] == "HKLM":
            parts[0] = "HKEY_LOCAL_MACHINE"
        self.set_hive(parts[0])
        self.set_path("\\".join(parts[1:]))

    def get_view(self):
        return self.view
    
    def get_hive(self):
        return self.hive

    def set_path(self, path):
        if path == '\\':
            path = ''
        self.path = path

    def get_path(self):
        return self.path

    def set_hive(self, hive):
        self.hive = hive

    def as_text(self):
        s = "Registry key: " + self.get_name() + "\n"
        if self.get_sd():
            s += self.get_sd().as_text()
        else:
            s += "[ERROR]"
        return s

    def get_parent_key(self):
        #print "get_parent_key called for: " + self.get_name()
        if not self.parent_key:
            mypath = self.get_name()
            # Check there is a parent_key dir - e.g. there isn't for "HKEY_LOCAL_MACHINE"
            if not mypath.find("\\") == -1:
                # check if only slash is at end of string: "HKEY_LOCAL_MACHINE\"
                if mypath.find("\\") == len(mypath) - 1:
                    self.parent_key = None
                else:
                    parent_keypath = "\\".join(mypath.split("\\")[0:-1])
                    # We frequently refer to parent_key dirs, so must cache and work we do
                    self.parent_key = wpc.conf.cache.regkey(parent_keypath)
            #        print self.parent_key
            else:
        #        print "[D] no parent_key dir"
                self.parent_key = None
        #if self.parent_key:
            #print "get_parent_key returning: " + str(self.parent_key.get_name())
        #else:
            #print "get_parent_key returning: None"
        return self.parent_key

    def get_issue_acl_for_perms(self, perms):
        if self.get_sd():
            al = self.get_sd().get_acelist().get_untrusted().get_aces_with_perms(perms).get_aces()
            if al == []:
                return None
            else:
                return issueAcl(self.get_name(), al)

    def dump(self):
        print self.as_text()

    def get_all_subkeys(self):
        for key in self.get_subkeys():
            yield key
            for k in key.get_all_subkeys():
                yield k

    def get_subkeys(self):
        subkey_objects = []
        try:
            subkeys = win32api.RegEnumKeyEx(self.get_keyh())
            for subkey in subkeys:
                subkey_objects.append(regkey(self.get_name() + "\\" + subkey[0], view=self.view))
        except:
            pass
        return subkey_objects

    def get_value(self, v):
        try:
            (data, type) = win32api.RegQueryValueEx(self.get_keyh(), v)
            return data
        except:
            return None

    def get_values(self):
        try:
            values = []
            (subkey_count, value_count, mod_time) = win32api.RegQueryInfoKey(self.get_keyh())
            for i in range(0, value_count):
                (s, o, t) = win32api.RegEnumValue(self.get_keyh(), i)
                values.append(s)
            return values
        except:
            return []

    def get_name(self):
        if self.path == '':
            return self.hive 
        return self.hive + "\\" + self.path

    def get_keyh(self):
        if not self.keyh:
            try:
                # self.keyh = win32api.RegOpenKeyEx(getattr(win32con, self.get_hive()), self.get_path(), 0, win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE | win32con.KEY_READ)
                if self.view is None:
                    self.keyh = win32api.RegOpenKeyEx(getattr(win32con, self.get_hive()), self.get_path(), 0, win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE | ntsecuritycon.READ_CONTROL)
                else:
                    if self.view == 32:
                        self.keyh = win32api.RegOpenKeyEx(getattr(win32con, self.get_hive()), self.get_path(), 0, win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE | ntsecuritycon.READ_CONTROL | win32con.KEY_WOW64_32KEY)
                    elif self.view == 64:
                        self.keyh = win32api.RegOpenKeyEx(getattr(win32con, self.get_hive()), self.get_path(), 0, win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE | ntsecuritycon.READ_CONTROL | win32con.KEY_WOW64_64KEY)
            except:
                pass
                # print "Can't open: " + self.get_name()
        return self.keyh

    def get_dangerous_aces(self):
        try:
            #print "[D] File: " + self.get_name()
            #print "[D] ACE: "
            #for a in self.get_sd().get_acelist().get_dangerous_perms().get_aces():
            #    print a.as_text()
            return self.get_sd().get_acelist().get_untrusted().get_dangerous_perms().get_aces()
        except:
            return []

    def is_present(self):
        return self.get_keyh()

    def get_sd(self):
        if self.sd is None:
            sd = None
            try:
                sd = win32api.RegGetKeySecurity(self.get_keyh(), win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION)
                self.sd = wpc.conf.cache.sd('regkey', sd)
                #print "[D]: Got security descriptor for " + self.get_name()
            except:
                # print "WARNING: Can't get security descriptor for regkey: " + self.get_name()
                self.sd = None

        return self.sd

    def get_type(self):
        return 'regkey'
    
    def as_tab(self, dangerous_only=1):
        lines = []
        lines.append(wpc.utils.tab_line("info", self.get_type(), str(self.get_name())))
        if self.get_sd():
            lines.append(wpc.utils.tab_line("gotsd", self.get_type(), str(self.get_name()), "yes"))
            lines.append(wpc.utils.tab_line("owner", self.get_type(), str(self.get_name()), str(self.get_sd().get_owner().get_fq_name())))         
            if self.get_sd().has_dacl():
                lines.append(wpc.utils.tab_line("hasdacl", self.get_type(), str(self.get_name()), "yes"))
                if dangerous_only:
                    lines.extend(self.get_sd().dangerous_aces_as_tab("ace", self.get_type(), str(self.get_name())))
                else:
                    lines.extend(self.get_sd().aces_as_tab("ace", self.get_type(), str(self.get_name())))
            else:
                lines.append(wpc.utils.tab_line("hasdacl", self.get_type(), str(self.get_name()), "no"))
        else:
            lines.append(wpc.utils.tab_line("gotsd", self.get_type(), str(self.get_name()), "no"))
        #print lines
        return "\n".join(lines)