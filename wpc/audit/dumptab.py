from wpc.scheduledtasks import scheduledtasks
from wpc.audit.auditbase import auditbase
from wpc.file import file as File
from wpc.groups import groups
from wpc.processes import processes
from wpc.process import process
from wpc.regkey import regkey
from wpc.services import drivers, services
from wpc.users import users
from wpc.user import user
from wpc.shares import shares
from wpc.drives import drives
from wpc.ntobj import ntobj
import pywintypes
import win32net
import os
import wpc.conf
import wpc.utils
import win32security

class dumptab(auditbase):
    def __init__(self, options, report):
        self.options = options
        self.report = report

    def run(self):
        self.run_sub("", 1,                                                         self.dumptab_misc_checks)
        self.run_sub("", self.options.do_all or self.options.do_paths,              self.dumptab_paths)
        self.run_sub("", self.options.do_allfiles,                                  self.dumptab_all_files)
        self.run_sub("", self.options.do_all or self.options.do_eventlogs,          self.dumptab_eventlogs)
        self.run_sub("", self.options.do_all or self.options.do_shares,             self.dumptab_shares)
        self.run_sub("", self.options.do_all or self.options.patchfile,             self.dumptab_patches)
        self.run_sub("", self.options.do_all or self.options.do_loggedin,           self.dumptab_loggedin)
        self.run_sub("", self.options.do_all or self.options.do_services,           self.dumptab_services)
        self.run_sub("", self.options.do_all or self.options.do_drivers,            self.dumptab_drivers)
        self.run_sub("", self.options.do_all or self.options.do_drives,             self.dumptab_drives)
        self.run_sub("", self.options.do_all or self.options.do_processes,          self.dumptab_processes)
        self.run_sub("", self.options.do_all or self.options.do_program_files,      self.dumptab_program_files)
        self.run_sub("", self.options.do_all or self.options.do_registry,           self.dumptab_registry)
        self.run_sub("", self.options.do_all or self.options.do_scheduled_tasks,    self.dumptab_scheduled_tasks)
        self.run_sub("", self.options.do_all or self.options.do_reg_keys,           self.dumptab_reg_keys)
        self.run_sub("", self.options.do_all or self.options.do_installed_software, self.dumptab_installed_software)
        self.run_sub("", self.options.do_all or self.options.do_nt_objects,         self.dumptab_nt_objects)
        self.run_sub("", self.options.do_all or self.options.do_users,              self.dumptab_users)
        self.run_sub("", self.options.do_all or self.options.do_groups,             self.dumptab_groups)
        self.run_sub("", self.options.do_all or self.options.get_modals,            self.dumptab_user_modals)

    # ---------------------- Define --dumptab Subs ---------------------------
    def dumptab_paths(self):
        paths = wpc.utils.get_user_paths()
    
        for path in paths:
            print wpc.utils.tab_line("info", "user_path", path[0].get_fq_name(), path[1])
    
        systempath = wpc.utils.get_system_path()
        print wpc.utils.tab_line("info", "system_path", systempath)
        
        
    def dumptab_scheduled_tasks(self):
        for task in scheduledtasks().get_all_tasks():
            print task.as_tab()
            
            
    def dumptab_all_files(self):
        # Record info about all directories
        include_dirs = 1
    
        #  Identify all NTFS drives
        prog_dirs = []
        for d in drives().get_fixed_drives():
            print wpc.utils.tab_line("info", "drive", d.get_name(), d.get_fs())
            if d.get_fs() == 'NTFS':
                prog_dirs.append(d.get_name())
    
        # Walk the directory tree of each NTFS drive
        for directory in prog_dirs:
            for filename in wpc.utils.dirwalk(directory, '*', include_dirs):
                f = File(filename)
                print f.as_tab()
    
    
    def dumptab_eventlogs(self):
        pass
    
    
    def dumptab_misc_checks(self):
        # Check if host is in a domain
        in_domain = 0
        dc_info = None
        try:
            dc_info = win32security.DsGetDcName(None, None, None, None, 0)
            in_domain = 1
        except:
            pass
    
        # DC information if available
        if in_domain:
            print wpc.utils.tab_line("info", "in_domain", "yes")
            for k in dc_info.keys():
                print wpc.utils.tab_line("info", "dc", k, dc_info[k])
        else:
            print wpc.utils.tab_line("info", "in_domain", "no")
    
        # misc information that appears in HTML report
        for i in ['hostname', 'datetime', 'version', 'user', 'domain', 'ipaddress', 'os', 'os_version']:
            print wpc.utils.tab_line("info", i, self.report.get_info_item(i))
            
            
    def dumptab_shares(self):
        for s in shares().get_all():
            print s.as_tab()
    
    
    def dumptab_patches(self):
        pass
    
    
    def dumptab_installed_software(self):
        uninstall = regkey('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall')
        if uninstall.is_present():
            for subkey in uninstall.get_subkeys():
                name = subkey.get_value("DisplayName")
                publisher = subkey.get_value("Publisher")
                version = subkey.get_value("DisplayVersion")
                date = subkey.get_value("InstallDate")
                if name:
                    print wpc.utils.tab_line("info", "installed_software", name, publisher, version, date)
    
            if process(os.getpid()).is_wow64():
                print '[+] Checking installed software (WoW64 enabled)'
                uninstall = regkey('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall', view=64)
                if uninstall.is_present():
                    for subkey in uninstall.get_subkeys():
                        name = subkey.get_value("DisplayName")
                        publisher = subkey.get_value("Publisher")
                        version = subkey.get_value("DisplayVersion")
                        date = subkey.get_value("InstallDate")
                        if name:
                            print wpc.utils.tab_line("info", "installed_software", name, publisher, version, date)
    
    def dumptab_loggedin(self):
        resume = 0
        try:
            while True:
                users, _, resume = win32net.NetWkstaUserEnum(wpc.conf.remote_server, 1 , resume , 999999 )
                for user in users:
                    u = "%s\\%s" % (user['logon_domain'], user['username'])
                    print wpc.utils.tab_line("info", "logged_in_user", u, user['logon_server'])
                if resume == 0:
                    break
        except:
            print "[E] Failed"
    
    def dumptab_services(self):
        for s in services().get_services():
            if s:
                print s.as_tab()
    
    
    def dumptab_drivers(self):
        for d in drivers().get_services():
            print d.as_tab()
    
    
    def dumptab_drives(self):
        for d in drives().get_fixed_drives():
            print wpc.utils.tab_line("info", "drive", d.get_name(), d.get_fs())
    
    
    def dumptab_processes(self):
        for p in processes().get_all():
            print p.as_tab()
    
    
    def dumptab_program_files(self):
        # Record info about all directories
        include_dirs = 1
    
        prog_dirs = []
        if os.getenv('ProgramFiles'):
            prog_dirs.append(os.environ['ProgramFiles'])
    
        if os.getenv('ProgramFiles(x86)'):
            prog_dirs.append(os.environ['ProgramFiles(x86)'])
    
        for directory in prog_dirs:
            # Walk program files directories looking for executables
            for filename in wpc.utils.dirwalk(directory, wpc.conf.executable_file_extensions, include_dirs):
                f = File(filename)
                print f.as_tab()
    
    
    def dumptab_registry(self):
        for r in regkey('HKLM').get_all_subkeys():
            print r.as_tab()
            
    
    def dumptab_reg_keys(self):
        pass
    
    
    def dumptab_nt_objects(self):
        for child in ntobj("\\").get_all_child_objects():
            print child.as_tab()
    
    
    def dumptab_users(self):
        userlist = users()
        for u in userlist.get_all():
            print wpc.utils.tab_line("info", "user", u.get_fq_name(), u.get_sid_string())
            
        for p in u.get_effective_privileges():
            print wpc.utils.tab_line("info", "user_effective_privilege", u.get_fq_name(), p)
    
        for priv in u.get_privileges():
            print wpc.utils.tab_line("info", "user_privilege", u.get_fq_name(), priv)
    
    
    def dumptab_groups(self):
        grouplist = groups()
        for g in grouplist.get_all():
            print wpc.utils.tab_line("info", "group", g.get_fq_name(), g.get_sid_string())
            for m in g.get_members():
                print wpc.utils.tab_line("info", "group_member", g.get_fq_name(), m.get_fq_name())
    
            for priv in g.get_privileges():
                print wpc.utils.tab_line("info", "group_privilege", g.get_fq_name(), priv)
    
    
    def dumptab_user_modals(self):
        d1 = d2 = d3 = d4 = {}
        try:
            d1 = win32net.NetUserModalsGet(wpc.conf.remote_server, 0)
            d2 = win32net.NetUserModalsGet(wpc.conf.remote_server, 1)
            d3 = win32net.NetUserModalsGet(wpc.conf.remote_server, 2)
            d4 = win32net.NetUserModalsGet(wpc.conf.remote_server, 3)
        except pywintypes.error as e:
            print "[E] %s: %s" % (e[1], e[2])
    
        for d in (d1, d2, d3, d4):
            for k in d.keys():
                print wpc.utils.tab_line("info", "user_modals", k, d[k])
    
    
