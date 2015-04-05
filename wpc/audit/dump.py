from wpc.scheduledtasks import scheduledtasks
from wpc.audit.auditbase import auditbase
import wpc.utils
import win32security
from wpc.shares import shares
from wpc.regkey import regkey
import win32net
import os
from wpc.file import file as File
from wpc.groups import groups
from wpc.processes import processes
from wpc.users import users
from wpc.user import user
from wpc.drives import drives
from wpc.ntobj import ntobj
from wpc.services import drivers, services
import pywintypes
import win32con
import win32service
from wpc.sd import sd
import win32process
import win32ts

class dump(auditbase):
    def __init__(self, options):
        self.options = options

    def run(self):    
        # TODO we don't have to pass options or issues to any subs
        self.run_sub("dump_misc_checks",   1,                                                    self.dump_misc_checks)
        self.run_sub("dump_paths",         self.options.do_all or self.options.do_paths,         self.dump_paths      )
        self.run_sub("dump_all_files",     self.options.do_allfiles,                             self.dump_all_files  )
        self.run_sub("dump_eventlogs",     self.options.do_all or self.options.do_eventlogs,     self.dump_eventlogs  )
        self.run_sub("dump_shares",        self.options.do_all or self.options.do_shares,        self.dump_shares     )
        self.run_sub("dump_patches",       self.options.do_all or self.options.patchfile,        self.dump_patches    )
        self.run_sub("dump_loggedin",      self.options.do_all or self.options.do_loggedin,      self.dump_loggedin   )
        self.run_sub("dump_services",      self.options.do_all or self.options.do_services,      self.dump_services   )
        self.run_sub("dump_drivers",       self.options.do_all or self.options.do_drivers,       self.dump_drivers    )
        self.run_sub("dump_drives",        self.options.do_all or self.options.do_drives,        self.dump_drives     )
        self.run_sub("dump_processes",     self.options.do_all or self.options.do_processes,     self.dump_processes  )
        self.run_sub("dump_program_files", self.options.do_all or self.options.do_program_files, self.dump_program_files)
        self.run_sub("dump_registry",      self.options.do_all or self.options.do_registry,      self.dump_registry   )
        self.run_sub("dump_scheduled_tasks",self.options.do_all or self.options.do_scheduled_tasks,self.dump_scheduled_tasks)
        self.run_sub("dump_reg_keys",      self.options.do_all or self.options.do_reg_keys,      self.dump_reg_keys   )
        self.run_sub("dump_nt_objects",    self.options.do_all or self.options.do_nt_objects,    self.dump_nt_objects )
        self.run_sub("dump_users",         self.options.do_all or self.options.do_users,         self.dump_users      )
        self.run_sub("dump_groups",        self.options.do_all or self.options.do_groups,        self.dump_groups     )
        self.run_sub("dump_user_modals",   self.options.do_all or self.options.get_modals,       self.dump_user_modals)
                    
    # ---------------------- Define --dump Subs ---------------------------
    def dump_paths(self):
        systempath = wpc.utils.get_system_path()
        print "System path: %s" % (systempath)
    
        paths = wpc.utils.get_user_paths()
    
        for path in paths:
            print "Path for user %s: %s" % (path[0].get_fq_name(), path[1])
    

    def dump_scheduled_tasks(self):
        for task in scheduledtasks().get_all_tasks():
            print task.as_text()
            
    def dump_misc_checks(self):
        # Check if host is in a domain
        in_domain = 0
        dc_info = None
        try:
            dc_info = win32security.DsGetDcName(None, None, None, None, 0)
            in_domain = 1
        except:
            pass
    
        if in_domain:
            print "[+] Host is in domain"
            for k in dc_info.keys():
                print "[-]   %s => %s" % (k, dc_info[k])
        else:
            print "[+] Host is not in domain"
    
    
    def dump_eventlogs(self):
        # TODO
        print "[E] dump_eventlogs not implemented yet.  Sorry."
    
    
    def dump_shares(self):
        for s in shares().get_all():
            print s.as_text()
    
    
    def dump_reg_keys(self):
        for check, key in wpc.conf.reg_keys.items():
            #print "Checking %s => %s" % (check, key)
            key_a = key.split('\\')
            value = key_a.pop()
            key_s = '\\'.join(key_a)
            rk = regkey(key_s)
            if rk.is_present:
                v = rk.get_value(value) # This value appears as "(Default)" in regedit
                print "Check: \"%s\", Key: %s, Value: %s, Data: %s" % (check, key_s, value, v)
    
    
    def dump_patches(self):
        # TODO
        print "[E] dump_patches not implemented yet.  Sorry."
    
    
    def dump_loggedin(self):
        resume = 0
        print "\n[+] Logged in users:"
        try:
            while True:
                users, _, resume = win32net.NetWkstaUserEnum(wpc.conf.remote_server, 1 , resume , 999999 )
                for user in users:
                    print "User logged in: Logon Server=\"%s\" Logon Domain=\"%s\" Username=\"%s\"" % (user['logon_server'], user['logon_domain'], user['username'])
                if resume == 0:
                    break
        except:
            print "[E] Failed"
    
    
    def dump_program_files(self):
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
                print f.as_text()
    
    
    def dump_services(self):
        for s in services().get_services():
            if s:
                print s.as_text()
            else:
                print "[W] Failed to get info about a service.  Skipping."
    
    
    def dump_drivers(self):
        for d in drivers().get_services():
            print d.as_text()
    
    
    def dump_drives(self):
        for d in drives().get_fixed_drives():
            print "%s: (%s)" % (d.get_name(), d.get_fs())
    
    
    def dump_processes(self):
        for p in processes().get_all():
            print p.as_text()
    
            # When listing DLLs for a process we need to see the filesystem like they do
            if p.is_wow64():
                wpc.utils.enable_wow64()
    
            if p.get_exe():
                print "Security Descriptor for Exe File %s" % p.get_exe().get_name()
                if p.get_exe().get_sd():
                    print p.get_exe().get_sd().as_text()
                else:
                    print "[unknown]"
    
                for dll in p.get_dlls():
                    print "\nSecurity Descriptor for DLL File %s" % dll.get_name()
                    sd = dll.get_sd()
                    if sd:
                        print sd.as_text()
    
            if p.is_wow64():
                wpc.utils.disable_wow64()
    
    
    def dump_users(self, get_privs = 0):
        print "[+] Dumping user list:"
        userlist = users()
        for u in userlist.get_all():
            print u.get_fq_name()
    
            if get_privs:
                print "\n\t[+] Privileges of this user:"
                for priv in u.get_privileges():
                    print "\t%s" % priv
        
                print "\n\t[+] Privileges of this user + the groups it is in:"
                for p in u.get_effective_privileges():
                    print "\t%s" % p
                print
    
    
    def dump_user_modals(self):
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
                print "%s: %s" % (k, d[k])
    
    def dump_groups(self, get_privs = 0):
        print "[+] Dumping group list:"
        grouplist = groups()
        for g in grouplist.get_all():
            group_name = g.get_fq_name()
    
            for m in g.get_members():
                print "%s has member: %s" % (group_name, m.get_fq_name())
    
            if get_privs:
                for priv in g.get_privileges():
                    print "%s has privilege: %s" % (group_name, priv)
    
            # TODO
            # print "\n\t[+] Privileges of this group + the groups it is in:"
            # for p in g.get_effective_privileges():
            #    print "\t%s" % p
    
    
    def dump_registry(self):
        for r in regkey('HKLM').get_all_subkeys():
            print r.as_text()
    
    
    def dump_nt_objects(self):
        
        #
        # Windows stations and Desktops - TODO make is more OO: objects for windowstations and desktops.
        #
        win32con.WINSTA_ALL_ACCESS = 0x0000037f
    
        print
        print "[-] Sessions"
        print
        for session in win32ts.WTSEnumerateSessions(win32ts.WTS_CURRENT_SERVER_HANDLE, 1, 0):
            print "SessionId: %s" % session['SessionId']
            print "\tWinStationName: %s" % session['WinStationName']
            print "\tState: %s" % session['State']
            print
    
        session = win32ts.ProcessIdToSessionId(win32process.GetCurrentProcessId())
        print
        print "[-] Winstations in session %s" % session
        print
        for w in win32service.EnumWindowStations():
            print "winstation: %s" % w
        print
    
        for w in win32service.EnumWindowStations():
            print
            print "[-] Session %s, Winstation '%s'" % (session, w)
            print
    
            # Get SD
            try:
                h = 0
                h = win32service.OpenWindowStation(w, False, win32con.READ_CONTROL)
                s = win32security.GetKernelObjectSecurity(h, win32security.OWNER_SECURITY_INFORMATION | win32security.GROUP_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
                s = sd('winstation', s)
                print s.as_text()
            except pywintypes.error,details:
                print "[E] Can't get READ_CONTROL winstation handle: %s" % details
    
            # Get Desktops
            try:
                h = 0
                h = win32service.OpenWindowStation(w, False, win32con.WINSTA_ENUMDESKTOPS)
                print "[-] Session %s, Winstation '%s' has these desktops:" % (session, w)
                for d in h.EnumDesktops():
                    print "\t%s" % d
                print
            except pywintypes.error,details:
                print "[E] Can't get WINSTA_ENUMDESKTOPS winstation handle: %s" % details
            if h:
                h.SetProcessWindowStation()
                for d in h.EnumDesktops():
                    print "[-] Session %s, Winstation '%s', Desktop '%s'" % (session, w, d)
                    try:
                        hd = win32service.OpenDesktop(d, 0, False, win32con.READ_CONTROL)
                        s = win32security.GetKernelObjectSecurity(hd, win32security.OWNER_SECURITY_INFORMATION | win32security.GROUP_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
                        s = sd('desktop', s)
                        print s.as_text()
                    except pywintypes.error,details:
                        print "[E] Can't get READ_CONTROL desktop handle: %s" % details
            print
    
        #
        # Objects
        #
        print
        print "[-] Objects"
        print
        root = ntobj("\\")
        for child in root.get_all_child_objects():
            print child.as_text()
            if (child.get_type() == "Semaphore" or child.get_type() == "Event" or child.get_type() == "Mutant" or child.get_type() == "Timer" or child.get_type() == "Section"  or child.get_type() == "Device" or child.get_type() == "SymbolicLink" or child.get_type() == "Key" or child.get_type() == "Directory") and child.get_sd():
                    print child.get_sd().as_text()
            else:
                print "Skipping unknown object type: %s" % child.get_type()
                print
    
    # Type - can't open
    # Device - can open, has sd
    # SymbolicLink - can open, has sd
    
    # TODO is this redundant now we have --dumptab?
    def dump_all_files(self):
        # Record info about all directories
        include_dirs = 1
    
        # TODO other drives too
    
        prog_dirs = []
        prog_dirs.append('c:\\')
    
        count = 0
        for dir in prog_dirs:
            # Walk program files directories looking for executables
            for filename in wpc.utils.dirwalk(dir, '*', include_dirs):
                f = File(filename)
                #print "[D] Processing %s" % f.get_name()
                # TODO check file owner, parent paths, etc.  Maybe use is_replaceable instead?
                aces = f.get_dangerous_aces()
                count = count + 1
                for ace in aces:
                    for p in ace.get_perms():
                        print "%s\t%s\t%s\t%s\t%s" % (f.get_type(), f.get_name(), ace.get_type(), ace.get_principal().get_fq_name(), p)
    
    
