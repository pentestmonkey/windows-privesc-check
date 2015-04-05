from wpc.audit.auditbase import auditbase
from wpc.file import file as File
from wpc.groups import groups
from wpc.processes import processes
from wpc.regkey import regkey
from wpc.services import drivers, services
from wpc.users import users
from wpc.user import user
from wpc.shares import shares
from wpc.drives import drives
from wpc.utils import k32, wow64
from wpc.patchdata import patchdata
from wpc.mspatchdb import mspatchdb
from wpc.exploit import exploit as exploit2
from wpc.ntobj import ntobj
import win32net
import subprocess
from lxml import objectify
import win32netcon
import urllib2
import ctypes
import os
import wpc.conf
import wpc.utils
import glob
import re
import win32security
import sys
from wpc.report.appendix import appendix
from wpc.softwarepackages import softwarepackages
from wpc.scheduledtasks import scheduledtasks

class audit(auditbase):
    def __init__(self, options, report):
        self.report = report
        self.issues = report.get_issues()
        self.appendices = report.get_appendices()
        self.options = options
        

    def run(self):
        self.run_sub("audit_misc_checks",        1,                                                         self.audit_misc_checks)
        self.run_sub("audit_paths",              self.options.do_all or self.options.do_paths,              self.audit_paths)
        self.run_sub("audit_eventlogs",          self.options.do_all or self.options.do_eventlogs,          self.audit_eventlogs)
        self.run_sub("audit_shares",             self.options.do_all or self.options.do_shares,             self.audit_shares)
        self.run_sub("audit_patches",            self.options.do_all or self.options.patchfile,             self.audit_patches)
        self.run_sub("audit_loggedin",           self.options.do_all or self.options.do_loggedin,           self.audit_loggedin)
        self.run_sub("audit_services",           self.options.do_all or self.options.do_services,           self.audit_services)
        self.run_sub("audit_drivers",            self.options.do_all or self.options.do_drivers,            self.audit_drivers)
        self.run_sub("audit_drives",             self.options.do_all or self.options.do_drives,             self.audit_drives)
        self.run_sub("audit_processes",          self.options.do_all or self.options.do_processes,          self.audit_processes)
        self.run_sub("audit_program_files",      self.options.do_all or self.options.do_program_files,      self.audit_program_files)
        self.run_sub("audit_registry",           self.options.do_all or self.options.do_registry,           self.audit_registry)
        self.run_sub("audit_scheduled_tasks",    self.options.do_all or self.options.do_scheduled_tasks,    self.audit_scheduled_tasks)
        self.run_sub("audit_reg_keys",           self.options.do_all or self.options.do_reg_keys,           self.audit_reg_keys)
        self.run_sub("audit_users",              self.options.do_all or self.options.do_users,              self.audit_users)
        self.run_sub("audit_nt_objects",         self.options.do_all or self.options.do_nt_objects,         self.audit_nt_objects)
        self.run_sub("audit_groups",             self.options.do_all or self.options.do_groups,             self.audit_groups)
        self.run_sub("audit_installed_software", self.options.do_all or self.options.do_installed_software, self.audit_installed_software)
        self.run_sub("audit_all_files (slow!)",  self.options.do_allfiles or self.options.interesting_file_list or self.options.interesting_file_file, self.audit_all_files, self.options)
        
    
    # ---------------------- Define --audit Subs ---------------------------
    def audit_misc_checks(self):
        # Check if host is in a domain
        in_domain = 0
        dc_info = None
        try:
            dc_info = win32security.DsGetDcName(None, None, None, None, 0)
            in_domain = 1
        except:
            pass
    
        if in_domain:
            self.issues.get_by_id("WPC092").add_supporting_data('dc_info', [dc_info])
        
        if wpc.utils.host_is_dc():      
            self.issues.get_by_id("WPC196").add_supporting_data('dc_info', [dc_info])
    
    
    def audit_installed_software(self):
        app = appendix("Installed Software")
        app.set_preamble("The following software was installed at the time of the audit.")
        app.add_table_row(["Name", "64 Bit?", "Version", "Date"])

        packages = softwarepackages()
        for package in packages.get_installed_packages():
            if self.options.do_appendices:
                fields = []
                fields.append(package.get_name())
                fields.append(package.get_arch())
                fields.append(package.get_version())
                fields.append(package.get_date())
                app.add_table_row(fields)

            # self.issues.get_by_id("WPC191").add_supporting_data('software', [package.get_name(), package.get_publisher(), package.get_version(), package.get_date()])
            
            if package.is_vulnerable_version():
                self.issues.get_by_id('WPC195').add_supporting_data('software_old', [package.get_name(), package.get_publisher(), package.get_version(), package.get_date(), package.get_bad_version()])
                
            for sw_category in wpc.conf.software.keys():
                if package.is_of_type(sw_category):
                    self.issues.get_by_id(wpc.conf.software[sw_category]['issue']).add_supporting_data('software', [package.get_name(), package.get_publisher(), package.get_version(), package.get_date()])

        if self.options.do_appendices:
            self.appendices.add_appendix(app)
    
    
    def audit_eventlogs(self):
        # TODO WPC009 Insecure Permissions On Event Log Registry Key
        key_string = "HKEY_LOCAL_MACHINE\\" + wpc.conf.eventlog_key_hklm
        eventlogkey = regkey(key_string)
        if eventlogkey.is_present():
            for subkey in eventlogkey.get_subkeys():
                # WPC008 Insecure Permissions On Event Log DLL
                filename = subkey.get_value("DisplayNameFile")
                if filename:
                    f = File(wpc.utils.env_expand(filename))
                    if f.is_replaceable():
                        self.issues.get_by_id("WPC008").add_supporting_data('writable_eventlog_dll', [subkey, f])
    
                    # WPC007 Insecure Permissions On Event Log File
                    # TODO should check for read access too
                    filename = subkey.get_value("File")
                    if filename:
                        f = File(wpc.utils.env_expand(filename))
                        # Check for write access
                        if f.is_replaceable():
                            self.issues.get_by_id("WPC007").add_supporting_data('writable_eventlog_file', [subkey, f])
    
                        # Check for read access
                        sd = f.get_sd()
                        if sd:
                            for a in sd.get_acelist().get_untrusted().get_aces_with_perms(["FILE_READ_DATA"]).get_aces():
                                self.issues.get_by_id("WPC088").add_supporting_data('file_read', [f, a.get_principal()])
    
    
    def audit_shares(self):
        app = appendix("Windows Shares")
        app.set_preamble("The following windows shares were configured at the time of the audit.")
        app.add_table_row(["Name", "Path", "Description"])

        for s in shares().get_all():
            if self.options.do_appendices:
                fields = []
                fields.append(s.get_name())
                fields.append(s.get_path())
                fields.append(s.get_description())
                app.add_table_row(fields)
    
            if s.get_sd():
                for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["FILE_READ_DATA"]).get_aces():
                    self.issues.get_by_id("WPC086").add_supporting_data('share_perms', [s, a.get_principal()])
    
        if self.options.do_appendices:
            self.appendices.add_appendix(app)
    
    
    def audit_reg_keys(self):
        r_root = regkey('HKEY_USERS')
        for r_user in r_root.get_subkeys():
            r = regkey(r_user.get_name() + '\\Control Panel\\Desktop')
            ss_active  = r.get_value("ScreenSaveActive")
            ss_exe     = r.get_value("SCRNSAVE.EXE")
            ss_secure  = r.get_value("ScreenSaverIsSecure")
            ss_timeout = r.get_value("ScreenSaveTimeout")
        
            # Lookup username for this registry branch
            m = re.search('HKEY_USERS.(S-[\d-]+)', r.get_name())
            u = None
            if m and m.group(1):
                string_sid = m.group(1)
                binary_sid = win32security.GetBinarySid(string_sid)
                u = user(binary_sid)
        
            # Screen saver is inactive
            if ss_active and int(ss_active) == 0:
                self.issues.get_by_id("WPC103").add_supporting_data('user_reg_keys', [u, r, "ScreenSaveActive", ss_active])
        
            # Screen saver is active
            elif ss_exe and int(ss_active) > 0:
        
                if int(ss_secure) > 0:
                    # should have low timeout
                    if int(ss_timeout) > int(wpc.conf.screensaver_max_timeout_secs):
                        self.issues.get_by_id("WPC091").add_supporting_data('user_reg_keys', [u, r, "ScreenSaveTimeout", ss_timeout])
                else:
                    # should ask for password
                    self.issues.get_by_id("WPC090").add_supporting_data('user_reg_keys', [u, r, "ScreenSaverIsSecure", ss_secure])
    
        # Windows autologon
        r = regkey('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', view=64)
        defaultuser = r.get_value("DefaultUserName")
        password = r.get_value("DefaultPassword")
        domain = r.get_value("DefaultDomainName")
        aal = r.get_value("AutoAdminLogon")
        if defaultuser is not None or password is not None or domain is not None or aal is not None:
            if defaultuser is None:
                defaultuser = "[not set]"
            if password is None:
                password = "[not set]"
            if domain is None:
                domain = "[not set]"
            if aal is None:
                aal = "[not set]"
            self.issues.get_by_id("WPC192").add_supporting_data('aal', ['HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', defaultuser, password, domain, aal])
        
        # UAC checks.  Note that we only report UAC misconfigurations when UAC is enabled.  If UAC
        #              is disabled, we just report that it's disabled.
        r = regkey('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System')
        v = r.get_value("EnableLUA")
        if v is not None:
            if v == 0:
                self.issues.get_by_id("WPC096").add_supporting_data('reg_key_value', [r, "EnableLUA", v])
            else:
                r = regkey('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System')
                v = r.get_value("ConsentPromptBehaviorAdmin")
                if v is not None:
                    if v == 0 or v == 5:
                        self.issues.get_by_id("WPC094").add_supporting_data('reg_key_value', [r, "ConsentPromptBehaviorAdmin", v])
    
                r = regkey('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System')
                v = r.get_value("FilterAdministratorToken")
                if v is not None:
                    if v == 0:
                        self.issues.get_by_id("WPC095").add_supporting_data('reg_key_value', [r, "FilterAdministratorToken", v])
    
                r = regkey('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System')
                v = r.get_value("PromptOnSecureDesktop")
                if v is not None:
                    if v == 0:
                        self.issues.get_by_id("WPC097").add_supporting_data('reg_key_value', [r, "PromptOnSecureDesktop", v])
    
        r = regkey('HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa')
        v = r.get_value("LmCompatibilityLevel")
        if v is not None:
            if v != 5:
                self.issues.get_by_id("WPC098").add_supporting_data('reg_key_value', [r, "LmCompatibilityLevel", v])
    
        r = regkey('HKLM\\System\\CurrentControlSet\\Control\\Lsa')
        v = r.get_value("NoLMHash")
        if v is not None:
            if v != 1:
                self.issues.get_by_id("WPC099").add_supporting_data('reg_key_value', [r, "NoLMHash", v])
    
        r = regkey('HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')
        v = r.get_value("CachedLogonsCount")
        if v is not None:
            if v != 1:
                self.issues.get_by_id("WPC100").add_supporting_data('reg_key_value', [r, "CachedLogonsCount", v])
    
        r = regkey('HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters')
        v = r.get_value("RequireSecuritySignature")
        if v is not None:
            if v != 1:
                self.issues.get_by_id("WPC101").add_supporting_data('reg_key_value', [r, "RequireSecuritySignature", v])
    
        r = regkey('HKLM\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters')
        v = r.get_value("RequireSecuritySignature")
        if v is not None:
            if v != 1:
                self.issues.get_by_id("WPC102").add_supporting_data('reg_key_value', [r, "RequireSecuritySignature", v])
    
        r = regkey('HKLM\\System\\CurrentControlSet\\Control\\Terminal Server')
        v = r.get_value("TSUserEnabled")
        if v is not None:
            if v == 1:
                self.issues.get_by_id("WPC106").add_supporting_data('reg_key_value', [r, "TSUserEnabled", v])
    
        r = regkey('HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager')
        v = r.get_value("CWDIllegalInDllSearch")
        if v is None or v == 0:
            self.issues.get_by_id("WPC107").add_supporting_data('reg_key_value', [r, "CWDIllegalInDllSearch", v])
    
        # Microsoft network client: Send unencrypted password to connect to third-party SMB servers
        r = regkey('HKLM\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters')
        v = r.get_value("EnablePlainTextPassword")
        if v == 1:
            self.issues.get_by_id("WPC172").add_supporting_data('reg_key_value', [r, "EnablePlainTextPassword", v])
    
        # TODO need to ignore this for domain controllers 
        # Network access: Do not allow anonymous enumeration of SAM accounts
        r = regkey('HKLM\\System\\CurrentControlSet\\Control\\Lsa')
        v = r.get_value("RestrictAnonymousSAM")
        if v == 0:
            self.issues.get_by_id("WPC173").add_supporting_data('reg_key_value', [r, "RestrictAnonymousSAM", v])
    
        # Network access: Do not allow anonymous enumeration of SAM accounts and shares
        r = regkey('HKLM\\System\\CurrentControlSet\\Control\\Lsa')
        v = r.get_value("RestrictAnonymous")
        if v is None or v == 0:
            self.issues.get_by_id("WPC174").add_supporting_data('reg_key_value', [r, "RestrictAnonymous", v])
    
        # Network access: Let Everyone permissions apply to anonymous users   
        r = regkey('HKLM\\System\\CurrentControlSet\\Control\\Lsa')
        v = r.get_value("EveryoneIncludesAnonymous")
        if v == 1:
            self.issues.get_by_id("WPC175").add_supporting_data('reg_key_value', [r, "EveryoneIncludesAnonymous", v])
    
        # Network access: Restrict anonymous access to Named Pipes and Shares 
        r = regkey('HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters')
        v = r.get_value("RestrictNullSessAccess")
        if v == 0:
            self.issues.get_by_id("WPC176").add_supporting_data('reg_key_value', [r, "RestrictNullSessAccess", v])
    
        # Network access: Shares that can be accessed anonymously              
        r = regkey('HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters')
        v = r.get_value("NullSessionShares")
        if v is not None and not v == "":
            self.issues.get_by_id("WPC177").add_supporting_data('reg_key_value', [r, "NullSessionShares", v])
    
        # Network security: Configure encryption types allowed for Kerberos 
        # TODO windows 7 / 2008 R2 or higher only 
        r = regkey('HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters')
        v = r.get_value("SupportedEncryptionTypes")
        if v is None or v & 1 or v & 2:
            self.issues.get_by_id("WPC178").add_supporting_data('reg_key_value', [r, "SupportedEncryptionTypes", v])
    
        # Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers 
        r = regkey('HKLM\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0')
        v = r.get_value("RestrictSendingNTLMTraffic")
        if v is None or v != 2:
            self.issues.get_by_id("WPC179").add_supporting_data('reg_key_value', [r, "RestrictSendingNTLMTraffic", v])
    
        # Network security: Restrict NTLM: Incoming NTLM traffic  
        r = regkey('HKLM\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0')
        v = r.get_value("RestrictReceivingNTLMTraffic")
        if v is None or v == 0:
            self.issues.get_by_id("WPC180").add_supporting_data('reg_key_value', [r, "RestrictReceivingNTLMTraffic", v])
    
        # Recovery console: Allow automatic administrative logon  
        r = regkey('HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Setup\\RecoveryConsole')
        v = r.get_value("SecurityLevel")
        if v == 1:
            self.issues.get_by_id("WPC181").add_supporting_data('reg_key_value', [r, "SecurityLevel", v])
    
        # System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links)
        r = regkey('HKLM\\System\\CurrentControlSet\\Control\\Session Manager')
        v = r.get_value("ProtectionMode")
        if v is None or v == 0:
            self.issues.get_by_id("WPC182").add_supporting_data('reg_key_value', [r, "ProtectionMode", v])
    
        # Network access: Do not allow storage of passwords and credentials for network authentication
        r = regkey('HKLM\\System\\CurrentControlSet\\Control\\Lsa')
        v = r.get_value("ProtectionMode")
        if v is None or v == 0:
            self.issues.get_by_id("WPC183").add_supporting_data('reg_key_value', [r, "disabledomaincreds", v])
    
    def audit_nt_objects(self):
        app = appendix("Windows Objects")
        app.set_preamble("The following windows objects were present at the time of the audit.")
        app.add_table_row(["Path", "Type"])

        root = ntobj("\\")
        issue_for = {
            'symboliclink': 'WPC122',
            'regkey': 'WPC123',
            'section': 'WPC124',
            'waitableport': 'WPC125',
            'windowstation': 'WPC126',
            'desktop': 'WPC127',
            'job': 'WPC128',
            'mutant': 'WPC129',
            'callback': 'WPC130',
            'keyedevent': 'WPC131',
            'event': 'WPC132',
            'device': 'WPC133',
            'directory': 'WPC134',
            'semaphore': 'WPC135',
        }
        # print issue_for.keys()
        for child in root.get_all_child_objects():
            if self.options.do_appendices:
                fields = []
                fields.append(child.get_path())
                fields.append(child.get_type())
                app.add_table_row(fields)
                # print child.as_text()
                
            if child.get_sd():
                if child.get_sd().has_no_dacl():
                    self.issues.get_by_id("WPC121").add_supporting_data('object_name_and_type', [child])
    
                for a in child.get_sd().get_acelist().get_untrusted().get_dangerous_perms().get_aces():
                    lc_type = child.get_type().lower()
                    if lc_type in issue_for.keys():
                        self.issues.get_by_id(issue_for[lc_type]).add_supporting_data('object_perms', [child, a])
                    else:
                        print "[W] No issue exists for object type: %s" % lc_type
    
        if self.options.do_appendices:
            self.appendices.add_appendix(app)

    
    def audit_patches(self):
        patchfile = self.options.patchfile
    
        if patchfile == 'auto':
            print "[-] Attempting to download patch info from Microsoft..."
            patchfile = 'ms-patch-info.xlsx'
            f = open(patchfile, 'wb')
            response = urllib2.urlopen('http://go.microsoft.com/fwlink/?LinkID=245778')
            html = response.read()
            f.write(html)
            f.close()
            print "[-] Download complete"
    
        try:
            f=open(patchfile, 'r')
            if f:
                f.close()
        except:
            print "[E] Can't open patch data file: %s" % patchfile
            return 0
    
        try:
            db = mspatchdb(patchfile)
    
        except:
            print "[E] Can't parse patch database.  Maybe file format has changed.  Skipping."
            return 0
    
        p = patchdata({'patchdb': db})
    
        print "[-] Gathering installed patches"
        print "[-] %s patches are installed" % len(p.get_installed_patches())
        os_string = p.get_os_string_for_ms_spreadsheet() 
        print "[-] OS string for Microsoft spreadsheet is: %s" % os_string
    
        # Populate list of known exploits
        exploit_list = []
        for line in wpc.conf.msexploitstring.split("\n"):
            m = re.search("([Mm][Ss]\d\d[_-]\d\d\d)", line)
            if m and m.group(1):
                e = exploit2()
                patch = m.group(1).upper()
                patch = patch.replace("_", "-")
                m = re.search("^\s*(\S+)\s+(\S+)\s+(\S+)\s+(.*)", line)
                if m:
                    e.set_title(m.group(4))
                    e.add_refno("MS Bulletin", patch)
                    e.set_info("Metasploit Exploit Name", m.group(1))
                    e.set_info("Reliability", m.group(3))
                    e.set_info("Date", m.group(2))
                    exploit_list.append(e)
    
        exploit_count = 0
        for e in exploit_list:
            if e.get_msno():
                if self.options.verbose:
                    print "[-] ---"
                    print "[-] There is a public exploit for %s.  Checking if patch has been applied..." % e.get_msno()
                if db.is_applicable(e.get_msno(), os_string):
                    if self.options.verbose:
                        print "[-] %s was applicable to %s" % (e.get_msno(), os_string)
                    if not p.msno_or_superseded_applied(e.get_msno(), os_string, 0):
                        exploit_count = exploit_count + 1
                        if self.options.verbose:
                            print e.as_string()
                        self.issues.get_by_id("WPC089").add_supporting_data('exploit_list', [e])
                else:
                    if self.options.verbose:
                        print "[-] Not vulnerable.  %s did not affect '%s'" % (e.get_msno(), os_string)
        print "[-] Found %s exploits potentially affecting this system" % exploit_count
    
    
    def audit_loggedin(self):
        resume = 0
        print "\n[+] Logged in users:"
        try:
            while True:
                users, _, resume = win32net.NetWkstaUserEnum(wpc.conf.remote_server, 1 , resume , 999999 )
                for user in users:
                    self.issues.get_by_id("WPC140").add_supporting_data('usernames', ["%s\\%s" % (user['logon_domain'], user['username'])])
                    print "User logged in: Logon Server=\"%s\" Logon Domain=\"%s\" Username=\"%s\"" % (user['logon_server'], user['logon_domain'], user['username'])
                if resume == 0:
                    break
        except:
            print "[E] Failed"
    
    
    def audit_drivers(self):
        app = appendix("Windows Drivers")
        app.set_preamble("The following windows drivers were present at the time of the audit.")
        app.add_table_row(["Shortname", "Longname", "Description", "Path"])
        for s in drivers().get_services():
            if self.options.do_appendices:
                fields = []
                fields.append(s.get_name())
                fields.append(s.get_description())
                fields.append(s.get_long_description())
                fields.append(s.get_exe_path_clean())
                app.add_table_row(fields)
                
            if s.get_reg_key() and s.get_reg_key().get_sd():
    
                # Check DACL set
                if not s.get_reg_key().get_sd().get_dacl():
                        self.issues.get_by_id("WPC141").add_supporting_data('service_regkey', [s])
                        
                # Check owner
                if not s.get_reg_key().get_sd().get_owner().is_trusted():
                    self.issues.get_by_id("WPC142").add_supporting_data('service_exe_regkey_untrusted_ownership', [s, s.get_reg_key()])
    
                # Untrusted users can change permissions
                acl = s.get_reg_key().get_issue_acl_for_perms(["WRITE_OWNER", "WRITE_DAC"])
                if acl:
                    self.issues.get_by_id("WPC143").add_supporting_data('service_reg_perms', [s, acl])
    
    #            "KEY_SET_VALUE", # GUI "Set Value".  Required to create, delete, or set a registry value.
                acl = s.get_reg_key().get_issue_acl_for_perms(["KEY_SET_VALUE"])
                if acl:
                    self.issues.get_by_id("WPC144").add_supporting_data('service_reg_perms', [s, acl])
    
    #            "KEY_CREATE_LINK", # GUI "Create Link".  Reserved for system use.
                acl = s.get_reg_key().get_issue_acl_for_perms(["KEY_CREATE_LINK"])
                if acl:
                    self.issues.get_by_id("WPC145").add_supporting_data('service_reg_perms', [s, acl])
    
    #            "KEY_CREATE_SUB_KEY", # GUI "Create subkey"
                acl = s.get_reg_key().get_issue_acl_for_perms(["KEY_CREATE_SUB_KEY"])
                if acl:
                    self.issues.get_by_id("WPC146").add_supporting_data('service_reg_perms', [s, acl])
    
    #            "DELETE", # GUI "Delete"
                acl = s.get_reg_key().get_issue_acl_for_perms(["DELETE"])
                if acl:
                    self.issues.get_by_id("WPC147").add_supporting_data('service_reg_perms', [s, acl])
    
                # TODO walk sub keys looking for weak perms - not necessarily a problem, but could be interesting
    
                # TODO checks on parent keys
                parent = s.get_reg_key().get_parent_key()
                while parent and parent.get_sd():
                    # Untrusted user owns parent directory
                    if not parent.get_sd().get_owner().is_trusted():
                        self.issues.get_by_id("WPC148").add_supporting_data('service_regkey_parent_untrusted_ownership', [s, parent])
    
                    # Parent dir can have file perms changed
                    fa = parent.get_issue_acl_for_perms(["WRITE_OWNER", "WRITE_DAC"])
                    if fa:
                        self.issues.get_by_id("WPC149").add_supporting_data('service_regkey_parent_perms', [s, fa])
    
                    # Child allows itself to be delete, parent allows it to be replaced
                    fa_parent = parent.get_issue_acl_for_perms(["DELETE"])
                    if fa_parent:
                        grandparent = parent.get_parent_key()
                        if grandparent and grandparent.get_sd():
                            # There is no "DELETE_CHILD" type permission within the registry.  Therefore for the delete+replace issue, 
                            # we only have one combination of permissions to look for: the key allows DELETE and the parent allows either 
                            # KEY_CREATE_SUB_KEY or KEY_CREATE_LINK
                            fa_grandparent = grandparent.get_issue_acl_for_perms(["KEY_CREATE_SUB_KEY", "KEY_CREATE_LINK"])
                            if fa_grandparent:
                                self.issues.get_by_id("WPC150").add_supporting_data('service_regkey_parent_grandparent_write_perms', [s, fa_parent, fa_grandparent])
    
                    parent = parent.get_parent_key()
    
            # Check that the binary name is properly quoted
            if str(s.get_exe_path_clean()).find(" ") > 0: # clean path contains a space
                if str(s.get_exe_path()).find(str('"' + s.get_exe_path_clean()) + '"') < 0: # TODO need regexp.  Could get false positive from this.
                    self.issues.get_by_id("WPC151").add_supporting_data('service_info', [s])
    
            #
            # Examine executable for service
            #
            if s.get_exe_file() and s.get_exe_file().get_sd():
    
                # Check DACL set
                if not s.get_exe_file().get_sd().get_dacl():
                        self.issues.get_by_id("WPC152").add_supporting_data('service_exe_no_dacl', [s])
                        
                # Examine parent directories
                parent = s.get_exe_file().get_parent_dir()
                while parent and parent.get_sd():
                    # Untrusted user owns parent directory
                    if not parent.get_sd().get_owner().is_trusted():
                        self.issues.get_by_id("WPC153").add_supporting_data('service_exe_parent_dir_untrusted_ownership', [s, parent])
    
                    # Parent dir can have file perms changed
                    fa = parent.get_file_acl_for_perms(["WRITE_OWNER", "WRITE_DAC"])
                    if fa:
                        self.issues.get_by_id("WPC154").add_supporting_data('service_exe_parent_dir_perms', [s, fa])
    
                    # Child allows itself to be delete, parent allows it to be replaced
                    fa_parent = parent.get_file_acl_for_perms(["DELETE"])
                    if fa_parent:
                        grandparent = parent.get_parent_dir()
                        if grandparent and grandparent.get_sd():
                            fa_grandparent = grandparent.get_file_acl_for_perms(["FILE_ADD_SUBFOLDER"])
                            if fa_grandparent:
                                self.issues.get_by_id("WPC155").add_supporting_data('service_exe_parent_grandparent_write_perms', [s, fa_parent, fa_grandparent])
    
                    # Parent allows child directory to be deleted and replaced
                    grandparent = parent.get_parent_dir()
                    if grandparent and grandparent.get_sd():
                        fa = grandparent.get_file_acl_for_perms(["FILE_DELETE_CHILD", "FILE_ADD_SUBFOLDER"])
                        if fa:
                            self.issues.get_by_id("WPC156").add_supporting_data('service_exe_parent_dir_perms', [s, fa])
    
                    parent = parent.get_parent_dir()
    
                # Untrusted user owns exe
                if not s.get_exe_file().get_sd().get_owner().is_trusted():
                    self.issues.get_by_id("WPC157").add_supporting_data('service_exe_owner', [s])
    
                # Check if exe can be appended to
                fa = s.get_exe_file().get_file_acl_for_perms(["FILE_APPEND_DATA"])
                if fa:
                    self.issues.get_by_id("WPC158").add_supporting_data('service_exe_write_perms', [s, fa])
    
                # Check if exe can be deleted and perhaps replaced
                fa = s.get_exe_file().get_file_acl_for_perms(["DELETE"])
                if fa:
                    # File can be delete (DoS issue)
                    self.issues.get_by_id("WPC159").add_supporting_data('service_exe_write_perms', [s, fa])
    
                    # File can be deleted and replaced (privesc issue)
                    parent = s.get_exe_file().get_parent_dir()
                    if parent and parent.get_sd():
                        fa_parent = parent.get_file_acl_for_perms(["FILE_ADD_FILE"])
                        if fa_parent:
                            self.issues.get_by_id("WPC160").add_supporting_data('service_exe_file_parent_write_perms', [s, fa, fa_parent])
    
                # Check for file perms allowing overwrite
                fa = s.get_exe_file().get_file_acl_for_perms(["FILE_WRITE_DATA", "WRITE_OWNER", "WRITE_DAC"])
                if fa:
                    self.issues.get_by_id("WPC161").add_supporting_data('service_exe_write_perms', [s, fa])
    
                # TODO write_file on a dir containing an exe might allow a dll to be added
            else:
                if not s.get_exe_file():
                    self.issues.get_by_id("WPC162").add_supporting_data('service_no_exe', [s])
    
            #
            # Examine security descriptor for service
            #
            if s.get_sd():
    
                # Check DACL is set
                if not s.get_sd().get_dacl():
                    self.issues.get_by_id("WPC171").add_supporting_data('service', [s])
    
                # TODO all mine are owned by SYSTEM.  Maybe this issue can never occur!?
                if not s.get_sd().get_owner().is_trusted():
                    self.issues.get_by_id("WPC163").add_supporting_data('principals_with_service_ownership', [s, s.get_sd().get_owner()])
    
                # SERVICE_START
                for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["SERVICE_START"]).get_aces():
                    self.issues.get_by_id("WPC164").add_supporting_data('principals_with_service_perm', [s, a.get_principal()])
    
                # SERVICE_STOP
                for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["SERVICE_STOP"]).get_aces():
                    self.issues.get_by_id("WPC165").add_supporting_data('principals_with_service_perm', [s, a.get_principal()])
    
                # SERVICE_PAUSE_CONTINUE
                for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["SERVICE_PAUSE_CONTINUE"]).get_aces():
                    self.issues.get_by_id("WPC166").add_supporting_data('principals_with_service_perm', [s, a.get_principal()])
    
                # SERVICE_CHANGE_CONFIG
                for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["SERVICE_CHANGE_CONFIG"]).get_aces():
                    self.issues.get_by_id("WPC167").add_supporting_data('principals_with_service_perm', [s, a.get_principal()])
    
                # DELETE
                for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["DELETE"]).get_aces():
                    self.issues.get_by_id("WPC168").add_supporting_data('principals_with_service_perm', [s, a.get_principal()])
    
                # WRITE_DAC
                for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["WRITE_DAC"]).get_aces():
                    self.issues.get_by_id("WPC169").add_supporting_data('principals_with_service_perm', [s, a.get_principal()])
    
                # WRITE_OWNER
                for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["WRITE_OWNER"]).get_aces():
                    self.issues.get_by_id("WPC170").add_supporting_data('principals_with_service_perm', [s, a.get_principal()])

        if self.options.do_appendices:
            self.appendices.add_appendix(app)
        
    
    def audit_drives(self):
        app = appendix("Drives")
        app.set_preamble("The following drives were present at the time of the audit.")
        app.add_table_row(["Name", "File System", "Type", "Fixed?"])

        for d in drives().get_fixed_drives():
            if self.options.do_appendices:
                fields = []
                fields.append(d.get_name())
                fields.append(d.get_fs())
                fields.append(d.get_type())
                fields.append(d.is_fixed_drive())
                app.add_table_row(fields)

            if d.get_fs() == 'NTFS':
    
                directory = File(d.get_name())
    
                for a in directory.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["FILE_ADD_FILE"]).get_aces():
                    self.issues.get_by_id("WPC010").add_supporting_data('dir_add_file', [directory, a])
    
                for a in directory.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["FILE_ADD_SUBDIRECTORY"]).get_aces():
                    self.issues.get_by_id("WPC087").add_supporting_data('dir_add_dir', [directory, a])
            else:
                self.issues.get_by_id("WPC011").add_supporting_data('drive_and_fs_list', [d])
    
        if self.options.do_appendices:
            self.appendices.add_appendix(app)
    
    def audit_processes(self):
        a = appendix("Running Processes")
        a.set_preamble("The following processes were running at the time of the audit.")
        a.add_table_row(["PID", "Name", "WoW64?", "Exe"])
        for p in processes().get_all():
            # TODO check the dangerous perms aren't held by the process owner
            if p.get_sd():
                if not p.get_sd().get_dacl():
                        self.issues.get_by_id("WPC136").add_supporting_data('process', [p])
                perms = p.get_sd().get_acelist().get_untrusted().get_dangerous_perms().get_aces()
                for perm in perms:
                    if p.get_token() and perm.get_principal().get_fq_name() != p.get_token().get_token_user().get_fq_name() and perm.get_principal().get_fq_name() != 'NT AUTHORITY\RESTRICTED':
                        self.issues.get_by_id("WPC069").add_supporting_data('process_perms', [p, perm])
    
            for t in p.get_threads():
                if t.get_sd():
                    perms = t.get_sd().get_acelist().get_untrusted().get_dangerous_perms().get_aces()
                    for perm in perms:
                        if p.get_token() and perm.get_principal().get_fq_name() != p.get_token().get_token_user().get_fq_name() and perm.get_principal().get_fq_name() != 'NT AUTHORITY\RESTRICTED':
                            self.issues.get_by_id("WPC104").add_supporting_data('thread_perms', [t, perm])
    
            for t in p.get_tokens():
                if t.get_sd():
                    perms = t.get_sd().get_acelist().get_untrusted().get_dangerous_perms().get_aces()
                    for perm in perms:
                        if perm.get_principal().get_fq_name() != 'NT AUTHORITY\RESTRICTED':
                            self.issues.get_by_id("WPC105").add_supporting_data('token_perms', [t, p, perm])
    
            # When listing DLLs for a process we need to see the filesystem like they do
            if p.is_wow64():
                k32.Wow64EnableWow64FsRedirection(ctypes.byref(wow64))
    
            if p.get_exe():
                if p.get_exe().is_replaceable():
                    self.issues.get_by_id("WPC067").add_supporting_data('process_exe', [p])
    
                    for dll in p.get_dlls():
                        if dll.is_replaceable():
                            self.issues.get_by_id("WPC068").add_supporting_data('process_dll', [p, dll])
    
            if p.is_wow64():
                k32.Wow64DisableWow64FsRedirection(ctypes.byref(wow64))
                
            if self.options.do_appendices:
                fields = []
                fields.append(p.get_pid())
                fields.append(p.get_short_name())
                wow64_status = "[unknown]"
                if p.is_wow64():
                    wow64_status = p.is_wow64()
                fields.append(wow64_status)
                exe_name = "[unknown]"
                if p.get_exe():
                    exe_name = p.get_exe().get_name()
                fields.append(exe_name)
                a.add_table_row(fields)
                
        if self.options.do_appendices:
            self.appendices.add_appendix(a)
    
    def audit_users(self):
        userlist = users()
        for u in userlist.get_all():
            flags = u.get_flags()
            
            # Defined in wpc/conf.py - ignore error in IDE
            if flags & win32netcon.UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED:
                self.issues.get_by_id("WPC108").add_supporting_data('username', [u])
    
            if not (flags & win32netcon.UF_ACCOUNTDISABLE or flags & win32netcon.UF_LOCKOUT):
                if u.get_password_age() > wpc.conf.max_password_age:
                    self.issues.get_by_id("WPC109").add_supporting_data('password_age', [u])
    
                if flags & win32netcon.UF_PASSWD_NOTREQD:
                    self.issues.get_by_id("WPC110").add_supporting_data('username', [u])
    
                if flags & win32netcon.UF_PASSWD_CANT_CHANGE:
                    self.issues.get_by_id("WPC111").add_supporting_data('username', [u])
    
                if flags & win32netcon.UF_DONT_EXPIRE_PASSWD:
                    self.issues.get_by_id("WPC112").add_supporting_data('username', [u])
    
                if flags & win32netcon.UF_TRUSTED_FOR_DELEGATION: # defined in wpc/conf.py
                    self.issues.get_by_id("WPC113").add_supporting_data('username', [u])
    
                if flags & win32netcon.UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION: # defined in wpc/conf.py
                    self.issues.get_by_id("WPC114").add_supporting_data('username', [u])
    
            # TODO consider other privs too
            # TODO remove useless privs
            # TODO More efficient method that doesn't involve looping through all users?  What does secpol.msc do?
            for p in u.get_effective_privileges():
                if p == "SeAssignPrimaryTokenPrivilege":
                    self.issues.get_by_id("WPC070").add_supporting_data('user_powerful_priv', [u])
                if p == "SeBackupPrivilege":
                    self.issues.get_by_id("WPC071").add_supporting_data('user_powerful_priv', [u])
                if p == "SeCreatePagefilePrivilege":
                    self.issues.get_by_id("WPC072").add_supporting_data('user_powerful_priv', [u])
                if p == "SeCreateTokenPrivilege":
                    self.issues.get_by_id("WPC073").add_supporting_data('user_powerful_priv', [u])
                if p == "SeDebugPrivilege":
                    self.issues.get_by_id("WPC074").add_supporting_data('user_powerful_priv', [u])
                if p == "SeEnableDelegationPrivilege":
                    self.issues.get_by_id("WPC075").add_supporting_data('user_powerful_priv', [u])
                if p == "SeLoadDriverPrivilege":
                    self.issues.get_by_id("WPC076").add_supporting_data('user_powerful_priv', [u])
                if p == "SeMachineAccountPrivilege":
                    self.issues.get_by_id("WPC077").add_supporting_data('user_powerful_priv', [u])
                if p == "SeManageVolumePrivilege":
                    self.issues.get_by_id("WPC078").add_supporting_data('user_powerful_priv', [u])
                if p == "SeRelabelPrivilege":
                    self.issues.get_by_id("WPC079").add_supporting_data('user_powerful_priv', [u])
                if p == "SeRestorePrivilege":
                    self.issues.get_by_id("WPC080").add_supporting_data('user_powerful_priv', [u])
                if p == "SeShutdownPrivilege":
                    self.issues.get_by_id("WPC081").add_supporting_data('user_powerful_priv', [u])
                if p == "SeSyncAgentPrivilege":
                    self.issues.get_by_id("WPC082").add_supporting_data('user_powerful_priv', [u])
                if p == "SeTakeOwnershipPrivilege":
                    self.issues.get_by_id("WPC083").add_supporting_data('user_powerful_priv', [u])
                if p == "SeTcbPrivilege":
                    self.issues.get_by_id("WPC084").add_supporting_data('user_powerful_priv', [u])
                if p == "SeTrustedCredManAccessPrivilege":
                    self.issues.get_by_id("WPC085").add_supporting_data('user_powerful_priv', [u])
    
    
    def audit_groups(self):
        grouplist = groups()
        for u in grouplist.get_all():
            # TODO ignore empty groups
            # TODO consider other privs too
            # TODO remove useless privs
            # TODO More efficient method that doesn't involve looping through all users?  What does secpol.msc do?
            for p in u.get_privileges():
                # print "\t%s" % p
                if p == "SeAssignPrimaryTokenPrivilege":
                    self.issues.get_by_id("WPC070").add_supporting_data('group_powerful_priv', [u])
                if p == "SeBackupPrivilege":
                    self.issues.get_by_id("WPC071").add_supporting_data('group_powerful_priv', [u])
                if p == "SeCreatePagefilePrivilege":
                    self.issues.get_by_id("WPC072").add_supporting_data('group_powerful_priv', [u])
                if p == "SeCreateTokenPrivilege":
                    self.issues.get_by_id("WPC073").add_supporting_data('group_powerful_priv', [u])
                if p == "SeDebugPrivilege":
                    self.issues.get_by_id("WPC074").add_supporting_data('group_powerful_priv', [u])
                if p == "SeEnableDelegationPrivilege":
                    self.issues.get_by_id("WPC075").add_supporting_data('group_powerful_priv', [u])
                if p == "SeLoadDriverPrivilege":
                    self.issues.get_by_id("WPC076").add_supporting_data('group_powerful_priv', [u])
                if p == "SeMachineAccountPrivilege":
                    self.issues.get_by_id("WPC077").add_supporting_data('group_powerful_priv', [u])
                if p == "SeManageVolumePrivilege":
                    self.issues.get_by_id("WPC078").add_supporting_data('group_powerful_priv', [u])
                if p == "SeRelabelPrivilege":
                    self.issues.get_by_id("WPC079").add_supporting_data('group_powerful_priv', [u])
                if p == "SeRestorePrivilege":
                    self.issues.get_by_id("WPC080").add_supporting_data('group_powerful_priv', [u])
                if p == "SeShutdownPrivilege":
                    self.issues.get_by_id("WPC081").add_supporting_data('group_powerful_priv', [u])
                if p == "SeSyncAgentPrivilege":
                    self.issues.get_by_id("WPC082").add_supporting_data('group_powerful_priv', [u])
                if p == "SeTakeOwnershipPrivilege":
                    self.issues.get_by_id("WPC083").add_supporting_data('group_powerful_priv', [u])
                if p == "SeTcbPrivilege":
                    self.issues.get_by_id("WPC084").add_supporting_data('group_powerful_priv', [u])
                if p == "SeTrustedCredManAccessPrivilege":
                    self.issues.get_by_id("WPC085").add_supporting_data('group_powerful_priv', [u])
    
    
    def audit_services(self):
        app = appendix("Windows Services")
        app.set_preamble("The following windows services were configured at the time of the audit.")
        app.add_table_row(["Shortname", "Longname", "Status", "Run As", "Description", "Path"])

        for s in services().get_services():
            if self.options.do_appendices:
                fields = []
                fields.append(s.get_name())
                fields.append(s.get_description())
                fields.append(s.get_status())
                fields.append(s.get_run_as())
                fields.append(s.get_long_description())
                fields.append(s.get_exe_path_clean())
                app.add_table_row(fields)
    
            #
            # Check if service runs as a domain/local user
            #
            u = s.get_run_as()
            if len(u.split("\\")) == 2:
                d = u.split("\\")[0]
                if not d in ("NT AUTHORITY", "NT Authority"):
                    if d in ("."):
                        # Local account - TODO better way to tell if acct is a local acct?
                        self.issues.get_by_id("WPC064").add_supporting_data('service_domain_user', [s])
                    else:
                        # Domain account - TODO better way to tell if acct is a domain acct?
                        self.issues.get_by_id("WPC063").add_supporting_data('service_domain_user', [s])
                        
            if len(u.split("@")) == 2:
                d = u.split("@")[1]
                if not d in ("NT AUTHORITY", "NT Authority"):
                    if d in ("."):
                        # Local account - TODO better way to tell if acct is a local acct?
                        self.issues.get_by_id("WPC064").add_supporting_data('service_domain_user', [s])
                    else:
                        # Domain account - TODO better way to tell if acct is a domain acct?
                        self.issues.get_by_id("WPC063").add_supporting_data('service_domain_user', [s])
    
            if s.get_name() in ("PSEXESVC", "Abel", "fgexec"):
                self.issues.get_by_id("WPC065").add_supporting_data('sectool_services', [s])
            elif s.get_description() in ("PsExec", "Abel", "fgexec"):
                self.issues.get_by_id("WPC065").add_supporting_data('sectool_services', [s])
            # TODO check for the presence of files - but not from here 
            #
            # Check if pentest/audit tools have accidentally been left running
            #
            # TODO: psexec
            # disp name = PsExec
            # Desc = blank
            # svc name = PSEXESVC
            # image = C:\WINDOWS\PSEXESVC.EXE
            #
            # TODO: abel
            # disp name = Abel
            # desc = blank
            # svc name = Abel
            # image = C:\WINDOWS\system32\spool\drivers\Abel.exe
            #
            # TODO: fgdump
            # image = %temp%\pwdump.exe
            # %temp%\lsremora.dll fgexec.exe cachedump.exe pstgdump.exe servpw64.exe cachedump64.exe 
            # lsremora64.dll servpw.exe
            # Examine registry key for service
            #
            if s.get_reg_key() and s.get_reg_key().get_sd():
    
                # Check DACL set
                if not s.get_reg_key().get_sd().get_dacl():
                        self.issues.get_by_id("WPC138").add_supporting_data('service_regkey', [s])
                        
                # Check owner
                if not s.get_reg_key().get_sd().get_owner().is_trusted():
                    self.issues.get_by_id("WPC035").add_supporting_data('service_exe_regkey_untrusted_ownership', [s, s.get_reg_key()])
    
                # Untrusted users can change permissions
                acl = s.get_reg_key().get_issue_acl_for_perms(["WRITE_OWNER", "WRITE_DAC"])
                if acl:
                    self.issues.get_by_id("WPC036").add_supporting_data('service_reg_perms', [s, acl])
    
    #            "KEY_SET_VALUE", # GUI "Set Value".  Required to create, delete, or set a registry value.
                acl = s.get_reg_key().get_issue_acl_for_perms(["KEY_SET_VALUE"])
                if acl:
                    self.issues.get_by_id("WPC037").add_supporting_data('service_reg_perms', [s, acl])
    
    #            "KEY_CREATE_LINK", # GUI "Create Link".  Reserved for system use.
                acl = s.get_reg_key().get_issue_acl_for_perms(["KEY_CREATE_LINK"])
                if acl:
                    self.issues.get_by_id("WPC038").add_supporting_data('service_reg_perms', [s, acl])
    
    #            "KEY_CREATE_SUB_KEY", # GUI "Create subkey"
                acl = s.get_reg_key().get_issue_acl_for_perms(["KEY_CREATE_SUB_KEY"])
                if acl:
                    self.issues.get_by_id("WPC039").add_supporting_data('service_reg_perms', [s, acl])
    
    #            "DELETE", # GUI "Delete"
                acl = s.get_reg_key().get_issue_acl_for_perms(["DELETE"])
                if acl:
                    self.issues.get_by_id("WPC040").add_supporting_data('service_reg_perms', [s, acl])
    
                # TODO walk sub keys looking for weak perms - not necessarily a problem, but could be interesting
    
                pkey = regkey(s.get_reg_key().get_name() + "\Parameters")
                if pkey.is_present():
                    v = pkey.get_value("ServiceDll")
                    if v:
                        f = File(wpc.utils.env_expand(v))
                        if f.exists():
                            if f.is_replaceable():
                                self.issues.get_by_id("WPC052").add_supporting_data('service_dll', [s, pkey, f])
    
                # TODO checks on parent keys
                parent = s.get_reg_key().get_parent_key()
                while parent and parent.get_sd():
                    # Untrusted user owns parent directory
                    if not parent.get_sd().get_owner().is_trusted():
                        self.issues.get_by_id("WPC041").add_supporting_data('service_regkey_parent_untrusted_ownership', [s, parent])
    
                    # Parent dir can have file perms changed
                    fa = parent.get_issue_acl_for_perms(["WRITE_OWNER", "WRITE_DAC"])
                    if fa:
                        self.issues.get_by_id("WPC042").add_supporting_data('service_regkey_parent_perms', [s, fa])
    
                    # Child allows itself to be delete, parent allows it to be replaced
                    fa_parent = parent.get_issue_acl_for_perms(["DELETE"])
                    if fa_parent:
                        grandparent = parent.get_parent_key()
                        if grandparent and grandparent.get_sd():
                            # There is no "DELETE_CHILD" type permission within the registry.  Therefore for the delete+replace issue, 
                            # we only have one combination of permissions to look for: the key allows DELETE and the parent allows either 
                            # KEY_CREATE_SUB_KEY or KEY_CREATE_LINK
                            fa_grandparent = grandparent.get_issue_acl_for_perms(["KEY_CREATE_SUB_KEY", "KEY_CREATE_LINK"])
                            if fa_grandparent:
                                self.issues.get_by_id("WPC043").add_supporting_data('service_regkey_parent_grandparent_write_perms', [s, fa_parent, fa_grandparent])
    
                    parent = parent.get_parent_key()
    
            # Check that the binary name is properly quoted
            if str(s.get_exe_path_clean()).find(" ") > 0: # clean path contains a space
                if str(s.get_exe_path()).find(str('"' + s.get_exe_path_clean()) + '"') < 0: # TODO need regexp.  Could get false positive from this.
                    self.issues.get_by_id("WPC051").add_supporting_data('service_info', [s])
    
            #
            # Examine executable for service
            #
            if s.get_exe_file() and s.get_exe_file().get_sd():
    
                # Check DACL set
                if not s.get_exe_file().get_sd().get_dacl():
                        self.issues.get_by_id("WPC139").add_supporting_data('service_exe_no_dacl', [s])
                        
                # Examine parent directories
                parent = s.get_exe_file().get_parent_dir()
                while parent and parent.get_sd():
                    # Untrusted user owns parent directory
                    if not parent.get_sd().get_owner().is_trusted():
                        self.issues.get_by_id("WPC033").add_supporting_data('service_exe_parent_dir_untrusted_ownership', [s, parent])
    
                    # Parent dir can have file perms changed
                    fa = parent.get_file_acl_for_perms(["WRITE_OWNER", "WRITE_DAC"])
                    if fa:
                        self.issues.get_by_id("WPC032").add_supporting_data('service_exe_parent_dir_perms', [s, fa])
    
                    # Child allows itself to be delete, parent allows it to be replaced
                    fa_parent = parent.get_file_acl_for_perms(["DELETE"])
                    if fa_parent:
                        grandparent = parent.get_parent_dir()
                        if grandparent and grandparent.get_sd():
                            fa_grandparent = grandparent.get_file_acl_for_perms(["FILE_ADD_SUBFOLDER"])
                            if fa_grandparent:
                                self.issues.get_by_id("WPC031").add_supporting_data('service_exe_parent_grandparent_write_perms', [s, fa_parent, fa_grandparent])
    
                    # Parent allows child directory to be deleted and replaced
                    grandparent = parent.get_parent_dir()
                    if grandparent and grandparent.get_sd():
                        fa = grandparent.get_file_acl_for_perms(["FILE_DELETE_CHILD", "FILE_ADD_SUBFOLDER"])
                        if fa:
                            self.issues.get_by_id("WPC030").add_supporting_data('service_exe_parent_dir_perms', [s, fa])
    
                    parent = parent.get_parent_dir()
    
                # Untrusted user owns exe
                if not s.get_exe_file().get_sd().get_owner().is_trusted():
                    self.issues.get_by_id("WPC029").add_supporting_data('service_exe_owner', [s])
    
                # Check if exe can be appended to
                fa = s.get_exe_file().get_file_acl_for_perms(["FILE_APPEND_DATA"])
                if fa:
                    self.issues.get_by_id("WPC027").add_supporting_data('service_exe_write_perms', [s, fa])
    
                # Check if exe can be deleted and perhaps replaced
                fa = s.get_exe_file().get_file_acl_for_perms(["DELETE"])
                if fa:
                    # File can be delete (DoS issue)
                    self.issues.get_by_id("WPC026").add_supporting_data('service_exe_write_perms', [s, fa])
    
                    # File can be deleted and replaced (privesc issue)
                    parent = s.get_exe_file().get_parent_dir()
                    if parent and parent.get_sd():
                        fa_parent = parent.get_file_acl_for_perms(["FILE_ADD_FILE"])
                        if fa_parent:
                            self.issues.get_by_id("WPC034").add_supporting_data('service_exe_file_parent_write_perms', [s, fa, fa_parent])
    
                # Check for file perms allowing overwrite
                fa = s.get_exe_file().get_file_acl_for_perms(["FILE_WRITE_DATA", "WRITE_OWNER", "WRITE_DAC"])
                if fa:
                    self.issues.get_by_id("WPC028").add_supporting_data('service_exe_write_perms', [s, fa])
    
                # TODO write_file on a dir containing an exe might allow a dll to be added
            else:
                if not s.get_exe_file():
                    self.issues.get_by_id("WPC062").add_supporting_data('service_no_exe', [s])
    
            #
            # Examine security descriptor for service
            #
            if s.get_sd():
    
                # Check DACL is set
                if not s.get_sd().get_dacl():
                    self.issues.get_by_id("WPC137").add_supporting_data('service', [s])
    
                # TODO all mine are owned by SYSTEM.  Maybe this issue can never occur!?
                if not s.get_sd().get_owner().is_trusted():
                    self.issues.get_by_id("WPC025").add_supporting_data('principals_with_service_ownership', [s, s.get_sd().get_owner()])
    
                # SERVICE_START
                for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["SERVICE_START"]).get_aces():
                    self.issues.get_by_id("WPC018").add_supporting_data('principals_with_service_perm', [s, a.get_principal()])
    
                # SERVICE_STOP
                for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["SERVICE_STOP"]).get_aces():
                    self.issues.get_by_id("WPC019").add_supporting_data('principals_with_service_perm', [s, a.get_principal()])
    
                # SERVICE_PAUSE_CONTINUE
                for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["SERVICE_PAUSE_CONTINUE"]).get_aces():
                    self.issues.get_by_id("WPC020").add_supporting_data('principals_with_service_perm', [s, a.get_principal()])
    
                # SERVICE_CHANGE_CONFIG
                for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["SERVICE_CHANGE_CONFIG"]).get_aces():
                    self.issues.get_by_id("WPC021").add_supporting_data('principals_with_service_perm', [s, a.get_principal()])
    
                # DELETE
                for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["DELETE"]).get_aces():
                    self.issues.get_by_id("WPC022").add_supporting_data('principals_with_service_perm', [s, a.get_principal()])
    
                # WRITE_DAC
                for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["WRITE_DAC"]).get_aces():
                    self.issues.get_by_id("WPC023").add_supporting_data('principals_with_service_perm', [s, a.get_principal()])
    
                # WRITE_OWNER
                for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["WRITE_OWNER"]).get_aces():
                    self.issues.get_by_id("WPC024").add_supporting_data('principals_with_service_perm', [s, a.get_principal()])
    
        if self.options.do_appendices:
            self.appendices.add_appendix(app)

    
    def csv_registry(self):
        print "[D] Walking registry"
        for r in regkey('HKLM').get_all_subkeys():
            aces = r.get_dangerous_aces()
            if aces:
                for a in aces:
                    for line in a.as_tab_delim(r.get_name()):
                        print line
                    for v in r.get_values(): 
                        for line in a.as_tab_delim3(r.get_name(), v, r.get_value(v)):
                            print line
    
    def audit_scheduled_tasks(self):
        app = appendix("Scheduled Tasks")
        app.set_preamble("The following Scheduled Tasks were configured at the time of the audit.")
        app.add_table_row(["Name", "Description", "Enabled", "SD", "Context", "Command"])

        for task in scheduledtasks().get_all_tasks():
            if self.options.do_appendices:
                fields = []
                fields.append(task.get_name())
                fields.append(task.get_description())
                fields.append(task.get_enabled())
                fields.append(task.get_sd_text())
                fields.append(task.get_action_context())
                fields.append(task.get_command_path())
                app.add_table_row(fields)

            #print task.get_command_path()
            # if task.get_enabled() and task.get_command_path():
            if 1 and task.get_command_path():
                f = File(task.get_command_path())
                print "[D] Processing %s" % task.get_command_path()
                if not f.exists():
                        self.issues.get_by_id("WPC197").add_supporting_data('taskfile', [task, f])                    
                if f.is_replaceable():
                    print "[D] Weak perms for: %s" % f.get_name()
                    for a in f.get_dangerous_aces():
                        self.issues.get_by_id("WPC120").add_supporting_data('scheduled_task_exe_perms', [f.get_name(), f, a])
                
        if self.options.do_appendices:
            self.appendices.add_appendix(app)

        
    def audit_registry(self):
    
        #
        # Shell Extensions
        #
    
        checks = (
            ["Context Menu", "WPC053", "HKLM\Software\Classes\*\ShellEx\ContextMenuHandlers"],
            ["Context Menu", "WPC053", "HKLM\Software\Wow6432Node\Classes\*\ShellEx\ContextMenuHandlers"],
            ["Context Menu", "WPC053", "HKLM\Software\Classes\Folder\ShellEx\ContextMenuHandlers"],
            ["Context Menu", "WPC053", "HKLM\Software\Wow6432Node\Classes\Folder\ShellEx\ContextMenuHandlers"],
            ["Context Menu", "WPC053", "HKLM\Software\Classes\Directory\ShellEx\ContextMenuHandlers"],
            ["Context Menu", "WPC053", "HKLM\Software\Wow6432Node\Classes\Directory\ShellEx\ContextMenuHandlers"],
            ["Context Menu", "WPC053", "HKLM\Software\Classes\AllFileSystemObjects\ShellEx\ContextMenuHandlers"],
            ["Context Menu", "WPC053", "HKLM\Software\Wow6432Node\Classes\AllFileSystemObjects\ShellEx\ContextMenuHandlers"],
            ["Context Menu", "WPC053", "HKLM\Software\Classes\Directory\Background\ShellEx\ContextMenuHandlers"],
            ["Context Menu", "WPC053", "HKLM\Software\Wow6432Node\Classes\Directory\Background\ShellEx\ContextMenuHandlers"],
    
            ["Property Sheet", "WPC054", "HKLM\Software\Classes\*\ShellEx\PropertySheetHandlers"],
            ["Property Sheet", "WPC054", "HKLM\Software\Wow6432Node\Classes\*\ShellEx\PropertySheetHandlers"],
            ["Property Sheet", "WPC054", "HKLM\Software\Classes\Folder\ShellEx\PropertySheetHandlers"],
            ["Property Sheet", "WPC054", "HKLM\Software\Wow6432Node\Classes\Folder\ShellEx\PropertySheetHandlers"],
            ["Property Sheet", "WPC054", "HKLM\Software\Classes\Directory\Shellex\PropertySheetHandlers"],
            ["Property Sheet", "WPC054", "HKLM\Software\Wow6432Node\Classes\Directory\Shellex\PropertySheetHandlers"],
            ["Property Sheet", "WPC054", "HKLM\Software\Classes\AllFileSystemObjects\ShellEx\PropertySheetHandlers"],
            ["Property Sheet", "WPC054", "HKLM\Software\Wow6432Node\Classes\AllFileSystemObjects\ShellEx\PropertySheetHandlers"],
    
            ["Copy Hook", "WPC055", "HKLM\Software\Classes\Directory\Shellex\CopyHookHandlers"],
            ["Copy Hook", "WPC055", "HKLM\Software\Wow6432Node\Classes\Directory\Shellex\CopyHookHandlers"],
    
            ["DragDrop Handler", "WPC056", "HKLM\Software\Classes\Directory\Shellex\DragDropHandlers"],
            ["DragDrop Handler", "WPC056", "HKLM\Software\Wow6432Node\Classes\Directory\Shellex\DragDropHandlers"],
            ["DragDrop Handler", "WPC056", "HKLM\Software\Classes\Folder\ShellEx\DragDropHandlers"],
            ["DragDrop Handler", "WPC056", "HKLM\Software\Wow6432Node\Classes\Folder\ShellEx\DragDropHandlers"],
    
            ["Column Handler", "WPC057", "HKLM\Software\Classes\Folder\Shellex\ColumnHandlers"],
            ["Column Handler", "WPC057", "HKLM\Software\Wow6432Node\Classes\Folder\Shellex\ColumnHandlers"],
        )
    
        for check in checks:
            check_type = check[0]
            check_id = check[1]
            check_key = check[2]
            rk = regkey(check_key)
            if rk.is_present:
                for s in rk.get_subkeys():
                    # TODO check regkey permissions
                    # TODO some of the subkeys are CLSIDs.  We don't process these properly yet.
                    clsid = s.get_value("") # This value appears as "(Default)" in regedit
                    if clsid:
                        reg_val_files = wpc.utils.lookup_files_for_clsid(clsid)
                        for reg_val_file in reg_val_files:
                            (r, v, f) = reg_val_file
                            if not f.exists():
                                f = wpc.utils.find_in_path(f)
    
                            if f and f.is_replaceable():
                                name = s.get_name().split("\\")[-1]
                                self.issues.get_by_id(check_id).add_supporting_data('regkey_ref_replacable_file', [check_type, name, clsid, f, s])
    
        #
        # Run, RunOnce, RunServices, RunServicesOnce
        #
    
        runkeys_hklm = (
            [ "WPC058", "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" ],
            [ "WPC058", "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" ],
            [ "WPC058", "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" ],
            [ "WPC058", "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce" ],
    
    # TODO RunOnceEx doesn't work like this.  Fix it.  See http://support.microsoft.com/kb/310593/
    #        [ "WPC058", "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx" ],
    #        [ "WPC058", "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx" ],
    
            [ "WPC059", "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunService" ],
            [ "WPC059", "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceService" ],
            [ "WPC059", "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunService" ],
            [ "WPC059", "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceService" ],
    
        # TODO what about HKCU - trawl for run keys of every single user?
        )
    
        for runkey_hklm in runkeys_hklm:
            issueid = runkey_hklm[0]
            rk = regkey(runkey_hklm[1])
    
            if rk.is_present:
                for v in rk.get_values():
                    # TODO check regkey permissions
                    imagepath = rk.get_value(v)
                    if imagepath:
                        f = File(wpc.utils.get_exe_path_clean(imagepath))
                        if f and f.is_replaceable():
                            self.issues.get_by_id(issueid).add_supporting_data('regkey_ref_file', [rk, v, f])
    
        #
        # KnownDlls
        #
    
        r = regkey("HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls")
    
        dirs = []
    
        d = r.get_value("DllDirectory")
        if d:
            dirs.append(wpc.utils.env_expand(d))
    
        d = r.get_value("DllDirectory32")
        if d:
            dirs.append(wpc.utils.env_expand(d))
    
        if r.is_present() and not dirs == []:
            for v in r.get_values():
                if v == "DllDirectory" or v == "DllDirectory32" or v == "":
                    continue
    
                file_str = r.get_value(v)
                for d in dirs:
                    if os.path.exists(d + "\\" + file_str):
                        f = File(d + "\\" + file_str)
                        if f.is_replaceable():
                            self.issues.get_by_id("WPC060").add_supporting_data('regkey_ref_file', [r, v, f])
    
        #
        # All CLSIDs (experimental)
        #
    
        results = []
        # Potentially intersting subkeys of clsids are listed here:
        # http://msdn.microsoft.com/en-us/library/windows/desktop/ms691424(v=vs.85).aspx
    
        # TODO doesn't report files that are not found or check perms of dll passed to rundll32.exe
        # [D] can't find %SystemRoot%\system32\eapa3hst.dll
        # [D] can't find rundll32.exe shell32.dll,SHCreateLocalServerRunDll {601ac3dc-786a-4eb0-bf40-ee3521e70bfb}
        # [D] can't find rundll32.exe C:\WINDOWS\system32\hotplug.dll,CreateLocalServer {783C030F-E948-487D-B35D-94FCF0F0C172}
        # [D] can't find rundll32.exe shell32.dll,SHCreateLocalServerRunDll {995C996E-D918-4a8c-A302-45719A6F4EA7}
        # [D] can't find rundll32.exe shell32.dll,SHCreateLocalServerRunDll {FFB8655F-81B9-4fce-B89C-9A6BA76D13E7}
    
        r = regkey("HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID")
        for clsid_key in r.get_subkeys():
            # print "[D] Processing clsid %s" % clsid_key.get_name()
            for v in ("InprocServer", "InprocServer32", "LocalServer", "LocalServer32"):
                s = regkey(clsid_key.get_name() + "\\" + v)
                if r.is_present:
                    f_str = s.get_value("") # "(Default)" value
                    if f_str:
                        f_str_expanded = wpc.utils.env_expand(f_str)
                        f = File(f_str_expanded)
                        if not f.exists():
                            f = wpc.utils.find_in_path(f)
    
                        if f and f.exists():
                            #print "[D] checking security of %s" % f.get_name()
                            pass
                        else:
    
                            f_str2 = wpc.utils.get_exe_path_clean(f_str_expanded)
                            if f_str2:
                                f = File(f_str2)
                            else:
                                #might be:
                                #"foo.exe /args"
                                #foo.exe /args
                                f_str2 = f_str.replace("\"", "")
                                f = wpc.utils.find_in_path(File(f_str2))
                                if not f or not f.exists():
                                    f_str2 = f_str2.split(" ")[0]
                                    f = wpc.utils.find_in_path(File(f_str2))
                                    # if f:
                                        # print "[D] how about %s" % f.get_name()
                        if not f:
                            # print "[D] can't find %s" % f_str
                            pass
    
                        if f and f.is_replaceable():
                            self.issues.get_by_id("WPC061").add_supporting_data('regkey_ref_file', [s, v, f])
    
        for key_string in wpc.conf.reg_paths:
            r = regkey(key_string)
    
            if r.get_sd():
    
                # Check owner
                if not r.get_sd().get_owner().is_trusted():
                    self.issues.get_by_id("WPC046").add_supporting_data('regkey_program_untrusted_ownership', [r])
    
                # Untrusted users can change permissions
                acl = r.get_issue_acl_for_perms(["WRITE_OWNER", "WRITE_DAC"])
                if acl:
                    self.issues.get_by_id("WPC047").add_supporting_data('regkey_perms', [r, acl])
    
    #            "KEY_SET_VALUE", # GUI "Set Value".  Required to create, delete, or set a registry value.
                acl = r.get_issue_acl_for_perms(["KEY_SET_VALUE"])
                if acl:
                    self.issues.get_by_id("WPC048").add_supporting_data('regkey_perms', [r, acl])
    
    #            "KEY_CREATE_LINK", # GUI "Create Link".  Reserved for system use.
                acl = r.get_issue_acl_for_perms(["KEY_CREATE_LINK", "KEY_CREATE_SUB_KEY"])
                if acl:
                    self.issues.get_by_id("WPC049").add_supporting_data('regkey_perms', [r, acl])
    
    #            "DELETE", # GUI "Delete"
                acl = r.get_issue_acl_for_perms(["DELETE"])
                if acl:
                    self.issues.get_by_id("WPC050").add_supporting_data('regkey_perms', [r, acl])
    
        print "[-] Walking registry (very slow: probably 15 mins - 1 hour)"
        for r in regkey('HKLM').get_all_subkeys():
            sd = r.get_sd()
            if sd:
                set_value_aces = sd.get_acelist().get_untrusted().get_aces_with_perms(["KEY_SET_VALUE"]).get_aces()
                if set_value_aces:
                    for v in r.get_values():
                        if wpc.utils.looks_like_executable(r.get_value(v)):
                            for a in set_value_aces:
                                self.issues.get_by_id("WPC115").add_supporting_data('regkey_value_data_perms', [r, v, repr(r.get_value(v)), a])
                        if wpc.utils.looks_like_path(r.get_value(v)):
                            for a in set_value_aces:
                                self.issues.get_by_id("WPC116").add_supporting_data('regkey_value_data_perms', [r, v, repr(r.get_value(v)), a])
                        if wpc.utils.looks_like_registry_path(r.get_value(v)):
                            for a in set_value_aces:
                                self.issues.get_by_id("WPC117").add_supporting_data('regkey_value_data_perms', [r, v, repr(r.get_value(v)), a])
                        if wpc.utils.looks_like_ip_address(r.get_value(v)):
                            for a in set_value_aces:
                                self.issues.get_by_id("WPC118").add_supporting_data('regkey_value_data_perms', [r, v, repr(r.get_value(v)), a])
                        if wpc.utils.looks_like_user(r.get_value(v)):
                            for a in set_value_aces:
                                self.issues.get_by_id("WPC119").add_supporting_data('regkey_value_data_perms', [r, v, repr(r.get_value(v)), a])
    
    
    # Gather info about files and directories
    def audit_program_files(self):
        # Record info about all directories
        include_dirs = 1
    
        prog_dirs = []
        if os.getenv('ProgramFiles'):
            prog_dirs.append(os.environ['ProgramFiles'])
    
        if os.getenv('ProgramFiles(x86)'):
            prog_dirs.append(os.environ['ProgramFiles(x86)'])
    
        for dir in prog_dirs:
            # Walk program files directories looking for executables
            for filename in wpc.utils.dirwalk(dir, wpc.conf.executable_file_extensions, include_dirs):
                f = File(filename)
                # TODO check file owner, parent paths, etc.  Maybe use is_replaceable instead?
                aces = f.get_dangerous_aces()
    
                for ace in aces:
                    if f.is_dir():
                        self.issues.get_by_id("WPC001").add_supporting_data('writable_dirs', [f, ace])
                    elif f.is_file():
                        self.issues.get_by_id("WPC001").add_supporting_data('writable_progs', [f, ace])    
                    else:
                        print "[E] Ignoring thing that isn't file or directory: " + f.get_name()
    
    
    def audit_all_files(self, options):
        # Record info about all directories
        include_dirs = 1
        prog_dirs = []
        
        # If user did not specify directory trees to descend with -f/-F, then do all fixed drives
        if options.interesting_file_list == [] and options.interesting_file_file is False:
            #  Identify all NTFS drives
            for d in drives().get_fixed_drives():
                prog_dirs.append(d.get_name())
        else:
            if options.interesting_file_list:
                prog_dirs = options.interesting_file_list
            if options.interesting_file_file:
                try:
                    prog_dirs = prog_dirs + [line.strip() for line in open(options.interesting_file_list)]
                except:
                    print "[E] Error reading from file %s" % options.interesting_file_list
                    sys.exit()
        
        print "[-] Processing the following directory trees:"
        for d in prog_dirs:
            print "[-] * %s" % d
            
        # Walk the directory tree of each NTFS drive
        for directory in prog_dirs:
            for filename in wpc.utils.dirwalk(directory, '*', include_dirs):
                # if we are only reporting readable interesting files, test for untrusted read access
                if not options.do_unreadable_if:
                    try:
                        file_obj = File(filename)
                        aces = file_obj.get_dangerous_aces_read()
                        if not aces:
                            continue
                    except:
                        continue
    #            for ace in aces:
    #                for p in ace.get_perms():
    #                    print "%s\t%s\t%s\t%s\t%s" % (f.get_type(), f.get_name(), ace.get_type(), ace.get_principal().get_fq_name(), p)
                #print "[D] Processing %s (%s)" % (filename, readable)
                f = os.path.basename(filename).lower()
                for check in wpc.conf.interesting_files['filename_exact_match']:
                    for check_file in check['filenames']:
                        if check_file.lower() == f:
                            self.issues.get_by_id(check['issue']).add_supporting_data('filename_string', [filename])
                            
                for check in wpc.conf.interesting_files['filename_regex_match']:
                    if re.search(check['regex'], f, re.IGNORECASE):
                        self.issues.get_by_id(check['issue']).add_supporting_data('filename_string', [filename])
                            
                for check in wpc.conf.interesting_files['filename_content_regex_match']:
                    if re.search(check['filename_regex'], f, re.IGNORECASE):
                        try:
                            # we need to apply the regex line-wize in case it's massive.  regex's need the whole string in memory.
                            for line in open(filename, 'r'):
                                #print "[D] line from %s: %s" % (filename, line)
                                if re.search(check['filename_content_regex'], line, re.IGNORECASE):
                                    self.issues.get_by_id(check['issue']).add_supporting_data('filename_string', [filename])
                                    break
                        except:
                            pass
                #if is_interesting:
                #    print "[D] Interesting file %s:" % filename
                #    for ace in aces:
                #        print ace.as_text()
        # TODO cleverly compile a summary of where weak permissions are
    
    def audit_paths(self):
    # TODO this will be too slow.  Need some clever caching.
    #    print "[-] Checking every user's path"
    #    for user_path in wpc.utils.get_user_paths():
    #        u = user_path[0]
    #        p = user_path[1]
    #        print "[D] Checking path of %s" % u.get_fq_name()
    #        # global tmp_trusted_principles_fq
    #        # tmp_trusted_principles_fq = (u.get_fq_name())  # TODO
    #        audit_path_for_issue(report, p, "WPC015")
    #        # tmp_trusted_principles_fq = ()  # TODO
    
        print "[-] Checking system path"
        self.audit_path_for_issue(wpc.utils.get_system_path(), "WPC013")
    
        print "[-] Checking current user's path"
        self.audit_path_for_issue(os.environ["PATH"], "WPC014")
    
    
    def audit_path_for_issue(self, mypath, issueid):
        dirs = set(mypath.split(';'))
        exts = wpc.conf.executable_file_extensions
        for dir in dirs:
            weak_flag = 0
            d = File(dir)
            aces = d.get_dangerous_aces()
            for ace in aces:
                self.issues.get_by_id(issueid).add_supporting_data('writable_dirs', [d, ace])
    
            for ext in exts:
                for myfile in glob.glob(dir + '\*.' + ext):
                    f = File(myfile)
                    aces = f.get_dangerous_aces()
                    for ace in aces:
                        self.issues.get_by_id(issueid).add_supporting_data('writable_progs', [f, ace])
    
            # TODO properly check perms with is_replaceable
    
    
