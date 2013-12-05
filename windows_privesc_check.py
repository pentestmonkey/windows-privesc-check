from wpc.file import file as File
from wpc.groups import groups
from wpc.parseOptions import parseOptions
from wpc.processes import processes
from wpc.regkey import regkey
from wpc.report.fileAcl import fileAcl
from wpc.report.report import report
from wpc.services import drivers, services
from wpc.users import users
from wpc.user import user
from wpc.shares import shares
from wpc.drives import drives
from wpc.utils import k32, wow64
from wpc.patchdata import patchdata
from wpc.mspatchdb import mspatchdb
from wpc.exploit import exploit as exploit2
import pywintypes
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

# ---------------------- Define Subs ---------------------------
def dump_paths(report):
    # TODO
    print "[E] dump_paths not implemented yet.  Sorry."


def dump_misc_checks(report):
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


def dump_eventlogs(report):
    # TODO
    print "[E] dump_eventlogs not implemented yet.  Sorry."


def dump_shares(report):
    for s in shares().get_all():
        print s.as_text()


def dump_reg_keys(report):
    for check, key in wpc.conf.reg_keys.items():
        #print "Checking %s => %s" % (check, key)
        key_a = key.split('\\')
        value = key_a.pop()
        key_s = '\\'.join(key_a)
        rk = regkey(key_s)
        if rk.is_present:
            v = rk.get_value(value) # This value appears as "(Default)" in regedit
            print "Check: \"%s\", Key: %s, Value: %s, Data: %s" % (check, key_s, value, v)


def dump_patches(report):
    # TODO
    print "[E] dump_patches not implemented yet.  Sorry."


def dump_loggedin(report):
    # TODO
    print "[E] dump_loggedin not implemented yet.  Sorry."


def dump_program_files(report):
    # TODO
    print "[E] dump_program_files not implemented yet.  Sorry."


def dump_services(opts):
    for s in services().get_services():
        print s.as_text()


def dump_drivers(opts):
    for d in drivers().get_services():
        print d.as_text()


def dump_drives(opts):
    print "[E] dump_drives not implemented yet.  Sorry."


def dump_processes(opts):
    for p in processes().get_all():
        print p.as_text()

        # When listing DLLs for a process we need to see the filesystem like they do
        if p.is_wow64():
            wpc.utils.enable_wow64()
            # k32.Wow64EnableWow64FsRedirection(ctypes.byref(wow64))

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
            # k32.Wow64DisableWow64FsRedirection(ctypes.byref(wow64))


def dump_users(opts, get_privs = 0):
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


def dump_user_modals(opts):
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

def dump_groups(opts, get_privs = 0):
    print "[+] Dumping group list:"
    grouplist = groups()
    for g in grouplist.get_all():
        group_name = g.get_fq_name()

        #if opts.get_members:
        #print "\n\t[+] Members:"
        for m in g.get_members():
            print "%s has member: %s" % (group_name, m.get_fq_name())

        if get_privs:
            #print "\n\t[+] Privileges of this group:"
            for priv in g.get_privileges():
                print "%s has privilege: %s" % (group_name, priv)

        # TODO
        # print "\n\t[+] Privileges of this group + the groups it is in:"
        # for p in g.get_effective_privileges():
        #    print "\t%s" % p


def dump_registry(opts):
    # TODO
    print "[!] Registry dump option not implemented yet.  Sorry."


def audit_misc_checks(report):
    # Check if host is in a domain
    in_domain = 0
    dc_info = None
    try:
        dc_info = win32security.DsGetDcName(None, None, None, None, 0)
        in_domain = 1
    except:
        pass

    if in_domain:
        report.get_by_id("WPC092").add_supporting_data('dc_info', [dc_info])


def audit_eventlogs(report):
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
                    report.get_by_id("WPC008").add_supporting_data('writable_eventlog_dll', [subkey, f])

                # WPC007 Insecure Permissions On Event Log File
                # TODO should check for read access too
                filename = subkey.get_value("File")
                if filename:
                    f = File(wpc.utils.env_expand(filename))
                    # Check for write access
                    if f.is_replaceable():
                        report.get_by_id("WPC007").add_supporting_data('writable_eventlog_file', [subkey, f])

                    # Check for read access
                    sd = f.get_sd()
                    if sd:
                        for a in sd.get_acelist().get_untrusted().get_aces_with_perms(["FILE_READ_DATA"]).get_aces():
                            report.get_by_id("WPC088").add_supporting_data('file_read', [f, a.get_principal()])


def audit_shares(report):
    for s in shares().get_all():
        #print s.as_text()

        if s.get_sd():
            for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["FILE_READ_DATA"]).get_aces():
                report.get_by_id("WPC086").add_supporting_data('share_perms', [s, a.get_principal()])


def audit_reg_keys(report):
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
            report.get_by_id("WPC103").add_supporting_data('user_reg_keys', [u, r, "ScreenSaveActive", ss_active])

        # Screen saver is active
        elif ss_exe and int(ss_active) > 0:

            if int(ss_secure) > 0:
                # should have low timeout
                if int(ss_timeout) > int(wpc.conf.screensaver_max_timeout_secs):
                    report.get_by_id("WPC091").add_supporting_data('user_reg_keys', [u, r, "ScreenSaveTimeout", ss_timeout])
            else:
                # should ask for password
                report.get_by_id("WPC090").add_supporting_data('user_reg_keys', [u, r, "ScreenSaverIsSecure", ss_secure])


    # UAC checks.  Note that we only report UAC misconfigurations when UAC is enabled.  If UAC
    #              is disabled, we just report that it's disabled.
    r = regkey('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System')
    v = r.get_value("EnableLUA")
    if v is not None:
        if v == 0:
            report.get_by_id("WPC096").add_supporting_data('reg_key_value', [r, "EnableLUA", v])
        else:
            r = regkey('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System')
            v = r.get_value("ConsentPromptBehaviorAdmin")
            if v is not None:
                if v == 0 or v == 5:
                    report.get_by_id("WPC094").add_supporting_data('reg_key_value', [r, "ConsentPromptBehaviorAdmin", v])

            r = regkey('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System')
            v = r.get_value("FilterAdministratorToken")
            if v is not None:
                if v == 0:
                    report.get_by_id("WPC095").add_supporting_data('reg_key_value', [r, "FilterAdministratorToken", v])

            r = regkey('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System')
            v = r.get_value("PromptOnSecureDesktop")
            if v is not None:
                if v == 0:
                    report.get_by_id("WPC097").add_supporting_data('reg_key_value', [r, "PromptOnSecureDesktop", v])

    r = regkey('HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa')
    v = r.get_value("LmCompatibilityLevel")
    if v is not None:
        if v != 5:
            report.get_by_id("WPC098").add_supporting_data('reg_key_value', [r, "LmCompatibilityLevel", v])

    r = regkey('HKLM\\System\\CurrentControlSet\\Control\\Lsa')
    v = r.get_value("NoLMHash")
    if v is not None:
        if v != 1:
            report.get_by_id("WPC099").add_supporting_data('reg_key_value', [r, "NoLMHash", v])

    r = regkey('HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')
    v = r.get_value("CachedLogonsCount")
    if v is not None:
        if v != 1:
            report.get_by_id("WPC100").add_supporting_data('reg_key_value', [r, "CachedLogonsCount", v])

    r = regkey('HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters')
    v = r.get_value("RequireSecuritySignature")
    if v is not None:
        if v != 1:
            report.get_by_id("WPC101").add_supporting_data('reg_key_value', [r, "RequireSecuritySignature", v])

    r = regkey('HKLM\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters')
    v = r.get_value("RequireSecuritySignature")
    if v is not None:
        if v != 1:
            report.get_by_id("WPC102").add_supporting_data('reg_key_value', [r, "RequireSecuritySignature", v])

    r = regkey('HKLM\\System\\CurrentControlSet\\Control\\Terminal Server')
    v = r.get_value("TSUserEnabled")
    if v is not None:
        if v == 1:
            report.get_by_id("WPC106").add_supporting_data('reg_key_value', [r, "TSUserEnabled", v])

    r = regkey('HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager')
    v = r.get_value("CWDIllegalInDllSearch")
    if v is None or v == 0:
        report.get_by_id("WPC107").add_supporting_data('reg_key_value', [r, "CWDIllegalInDllSearch", v])


def audit_patches(report):
    patchfile = options.patchfile

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
            if options.verbose:
                print "[-] ---"
                print "[-] There is a public exploit for %s.  Checking if patch has been applied..." % e.get_msno()
            if db.is_applicable(e.get_msno(), os_string):
                if options.verbose:
                    print "[-] %s was applicable to %s" % (e.get_msno(), os_string)
                if not p.msno_or_superseded_applied(e.get_msno(), os_string, 0):
                    exploit_count = exploit_count + 1
                    if options.verbose:
                        print e.as_string()
                    report.get_by_id("WPC089").add_supporting_data('exploit_list', [e])
            else:
                if options.verbose:
                    print "[-] Not vulnerable.  %s did not affect '%s'" % (e.get_msno(), os_string)
    print "[-] Found %s exploits potentially affecting this system" % exploit_count


def audit_loggedin(report):
    # TODO
    print "[E] audit_loggedin not implemented yet.  Sorry."


def audit_drivers(report):
    # TODO
    print "[E] Driver audit option not implemented yet.  Sorry."


def audit_drives(report):
    for d in drives().get_fixed_drives():
        if d.get_fs() == 'NTFS':
#            for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["FILE_WRITE_DATA"]).get_aces():

            directory = File(d.get_name())

            for a in directory.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["FILE_ADD_FILE"]).get_aces():
                report.get_by_id("WPC010").add_supporting_data('dir_add_file', [directory, a])

            for a in directory.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["FILE_ADD_SUBDIRECTORY"]).get_aces():
                report.get_by_id("WPC087").add_supporting_data('dir_add_dir', [directory, a])
        else:
            report.get_by_id("WPC011").add_supporting_data('drive_and_fs_list', [d])


def audit_processes(report):
    for p in processes().get_all():
        #print p.as_text()

        #print "[D] Dangerous process perms"
        # TODO check the dangerous perms aren't held by the process owner
        if p.get_sd():
            perms = p.get_sd().get_acelist().get_untrusted().get_dangerous_perms().get_aces()
            for perm in perms:
                if p.get_token() and perm.get_principal().get_fq_name() != p.get_token().get_token_user().get_fq_name() and perm.get_principal().get_fq_name() != 'NT AUTHORITY\RESTRICTED':
                    report.get_by_id("WPC069").add_supporting_data('process_perms', [p, perm])

        for t in p.get_threads():
            if t.get_sd():
                perms = t.get_sd().get_acelist().get_untrusted().get_dangerous_perms().get_aces()
                for perm in perms:
                    #print p.as_text()
                    if p.get_token() and perm.get_principal().get_fq_name() != p.get_token().get_token_user().get_fq_name() and perm.get_principal().get_fq_name() != 'NT AUTHORITY\RESTRICTED':
                        # print t.get_sd().as_text()
                        report.get_by_id("WPC104").add_supporting_data('thread_perms', [t, perm])
        #print "[D] End"

        for t in p.get_tokens():
            if t.get_sd():
                perms = t.get_sd().get_acelist().get_untrusted().get_dangerous_perms().get_aces()
                for perm in perms:
                    #print p.as_text()
                    if perm.get_principal().get_fq_name() != 'NT AUTHORITY\RESTRICTED':
                        # print t.get_sd().as_text()
                        report.get_by_id("WPC105").add_supporting_data('token_perms', [t, p, perm])

        # When listing DLLs for a process we need to see the filesystem like they do
        if p.is_wow64():
            k32.Wow64EnableWow64FsRedirection(ctypes.byref(wow64))

        if p.get_exe():
            if p.get_exe().is_replaceable():
                report.get_by_id("WPC067").add_supporting_data('process_exe', [p])
                #print "[D] Security Descriptor for replaceable Exe File %s" % p.get_exe().get_name()
                #if p.get_exe().get_sd():
                #    print p.get_exe().get_sd().as_text()
                #else:
                #    print "[unknown]"

                for dll in p.get_dlls():
                    if dll.is_replaceable():
                        report.get_by_id("WPC068").add_supporting_data('process_dll', [p, dll])
                        #print "\nSecurity Descriptor for replaceable DLL File %s" % dll.get_name()
                        #print dll.get_sd().as_text()

        if p.is_wow64():
            k32.Wow64DisableWow64FsRedirection(ctypes.byref(wow64))


def audit_users(report):
    userlist = users()
    for u in userlist.get_all():
        flags = u.get_flags()
        
        if flags & win32netcon.UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED:
            report.get_by_id("WPC108").add_supporting_data('username', [u])

        if not (flags & win32netcon.UF_ACCOUNTDISABLE or flags & win32netcon.UF_LOCKOUT):
            if u.get_password_age() > wpc.conf.max_password_age:
                report.get_by_id("WPC109").add_supporting_data('password_age', [u])

            if flags & win32netcon.UF_PASSWD_NOTREQD:
                report.get_by_id("WPC110").add_supporting_data('username', [u])

            if flags & win32netcon.UF_PASSWD_CANT_CHANGE:
                report.get_by_id("WPC111").add_supporting_data('username', [u])

            if flags & win32netcon.UF_DONT_EXPIRE_PASSWD:
                report.get_by_id("WPC112").add_supporting_data('username', [u])

            if flags & win32netcon.UF_TRUSTED_FOR_DELEGATION:
                report.get_by_id("WPC113").add_supporting_data('username', [u])

            if flags & win32netcon.UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
                report.get_by_id("WPC114").add_supporting_data('username', [u])

        # TODO consider other privs too
        # TODO remove useless privs
        # TODO More efficient method that doesn't involve looping through all users?  What does secpol.msc do?
        for p in u.get_effective_privileges():
            # print "\t%s" % p
            if p == "SeAssignPrimaryTokenPrivilege":
                report.get_by_id("WPC070").add_supporting_data('user_powerful_priv', [u])
            if p == "SeBackupPrivilege":
                report.get_by_id("WPC071").add_supporting_data('user_powerful_priv', [u])
            if p == "SeCreatePagefilePrivilege":
                report.get_by_id("WPC072").add_supporting_data('user_powerful_priv', [u])
            if p == "SeCreateTokenPrivilege":
                report.get_by_id("WPC073").add_supporting_data('user_powerful_priv', [u])
            if p == "SeDebugPrivilege":
                report.get_by_id("WPC074").add_supporting_data('user_powerful_priv', [u])
            if p == "SeEnableDelegationPrivilege":
                report.get_by_id("WPC075").add_supporting_data('user_powerful_priv', [u])
            if p == "SeLoadDriverPrivilege":
                report.get_by_id("WPC076").add_supporting_data('user_powerful_priv', [u])
            if p == "SeMachineAccountPrivilege":
                report.get_by_id("WPC077").add_supporting_data('user_powerful_priv', [u])
            if p == "SeManageVolumePrivilege":
                report.get_by_id("WPC078").add_supporting_data('user_powerful_priv', [u])
            if p == "SeRelabelPrivilege":
                report.get_by_id("WPC079").add_supporting_data('user_powerful_priv', [u])
            if p == "SeRestorePrivilege":
                report.get_by_id("WPC080").add_supporting_data('user_powerful_priv', [u])
            if p == "SeShutdownPrivilege":
                report.get_by_id("WPC081").add_supporting_data('user_powerful_priv', [u])
            if p == "SeSyncAgentPrivilege":
                report.get_by_id("WPC082").add_supporting_data('user_powerful_priv', [u])
            if p == "SeTakeOwnershipPrivilege":
                report.get_by_id("WPC083").add_supporting_data('user_powerful_priv', [u])
            if p == "SeTcbPrivilege":
                report.get_by_id("WPC084").add_supporting_data('user_powerful_priv', [u])
            if p == "SeTrustedCredManAccessPrivilege":
                report.get_by_id("WPC085").add_supporting_data('user_powerful_priv', [u])


def audit_groups(report):
    grouplist = groups()
    for u in grouplist.get_all():
        #print u.get_fq_name()

        # TODO ignore empty groups
        # TODO consider other privs too
        # TODO remove useless privs
        # TODO More efficient method that doesn't involve looping through all users?  What does secpol.msc do?
        for p in u.get_privileges():
            # print "\t%s" % p
            if p == "SeAssignPrimaryTokenPrivilege":
                report.get_by_id("WPC070").add_supporting_data('group_powerful_priv', [u])
            if p == "SeBackupPrivilege":
                report.get_by_id("WPC071").add_supporting_data('group_powerful_priv', [u])
            if p == "SeCreatePagefilePrivilege":
                report.get_by_id("WPC072").add_supporting_data('group_powerful_priv', [u])
            if p == "SeCreateTokenPrivilege":
                report.get_by_id("WPC073").add_supporting_data('group_powerful_priv', [u])
            if p == "SeDebugPrivilege":
                report.get_by_id("WPC074").add_supporting_data('group_powerful_priv', [u])
            if p == "SeEnableDelegationPrivilege":
                report.get_by_id("WPC075").add_supporting_data('group_powerful_priv', [u])
            if p == "SeLoadDriverPrivilege":
                report.get_by_id("WPC076").add_supporting_data('group_powerful_priv', [u])
            if p == "SeMachineAccountPrivilege":
                report.get_by_id("WPC077").add_supporting_data('group_powerful_priv', [u])
            if p == "SeManageVolumePrivilege":
                report.get_by_id("WPC078").add_supporting_data('group_powerful_priv', [u])
            if p == "SeRelabelPrivilege":
                report.get_by_id("WPC079").add_supporting_data('group_powerful_priv', [u])
            if p == "SeRestorePrivilege":
                report.get_by_id("WPC080").add_supporting_data('group_powerful_priv', [u])
            if p == "SeShutdownPrivilege":
                report.get_by_id("WPC081").add_supporting_data('group_powerful_priv', [u])
            if p == "SeSyncAgentPrivilege":
                report.get_by_id("WPC082").add_supporting_data('group_powerful_priv', [u])
            if p == "SeTakeOwnershipPrivilege":
                report.get_by_id("WPC083").add_supporting_data('group_powerful_priv', [u])
            if p == "SeTcbPrivilege":
                report.get_by_id("WPC084").add_supporting_data('group_powerful_priv', [u])
            if p == "SeTrustedCredManAccessPrivilege":
                report.get_by_id("WPC085").add_supporting_data('group_powerful_priv', [u])


def audit_services(report):
    for s in services().get_services():

        #
        # Check if service runs as a domain/local user
        #
        u = s.get_run_as()
        if len(u.split("\\")) == 2:
            d = u.split("\\")[0]
            if not d in ("NT AUTHORITY", "NT Authority"):
                if d in ("."):
                    # Local account - TODO better way to tell if acct is a local acct?
                    report.get_by_id("WPC064").add_supporting_data('service_domain_user', [s])
                else:
                    # Domain account - TODO better way to tell if acct is a domain acct?
                    report.get_by_id("WPC063").add_supporting_data('service_domain_user', [s])

        if s.get_name() in ("PSEXESVC", "Abel", "fgexec"):
            report.get_by_id("WPC065").add_supporting_data('sectool_services', [s])
        elif s.get_description() in ("PsExec", "Abel", "fgexec"):
            report.get_by_id("WPC065").add_supporting_data('sectool_services', [s])

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

            # Check owner
            if not s.get_reg_key().get_sd().get_owner().is_trusted():
                report.get_by_id("WPC035").add_supporting_data('service_exe_regkey_untrusted_ownership', [s, s.get_reg_key()])

            # Untrusted users can change permissions
            acl = s.get_reg_key().get_issue_acl_for_perms(["WRITE_OWNER", "WRITE_DAC"])
            if acl:
                report.get_by_id("WPC036").add_supporting_data('service_reg_perms', [s, acl])

#            "KEY_SET_VALUE", # GUI "Set Value".  Required to create, delete, or set a registry value.
            acl = s.get_reg_key().get_issue_acl_for_perms(["KEY_SET_VALUE"])
            if acl:
                report.get_by_id("WPC037").add_supporting_data('service_reg_perms', [s, acl])

#            "KEY_CREATE_LINK", # GUI "Create Link".  Reserved for system use.
            acl = s.get_reg_key().get_issue_acl_for_perms(["KEY_CREATE_LINK"])
            if acl:
                report.get_by_id("WPC038").add_supporting_data('service_reg_perms', [s, acl])

#            "KEY_CREATE_SUB_KEY", # GUI "Create subkey"
            acl = s.get_reg_key().get_issue_acl_for_perms(["KEY_CREATE_SUB_KEY"])
            if acl:
                report.get_by_id("WPC039").add_supporting_data('service_reg_perms', [s, acl])

#            "DELETE", # GUI "Delete"
            acl = s.get_reg_key().get_issue_acl_for_perms(["DELETE"])
            if acl:
                report.get_by_id("WPC040").add_supporting_data('service_reg_perms', [s, acl])

            # TODO walk sub keys looking for weak perms - not necessarily a problem, but could be interesting

            pkey = regkey(s.get_reg_key().get_name() + "\Parameters")
            if pkey.is_present():
                v = pkey.get_value("ServiceDll")
                if v:
                    f = File(wpc.utils.env_expand(v))
                    if f.exists():
                        if f.is_replaceable():
                            report.get_by_id("WPC052").add_supporting_data('service_dll', [s, pkey, f])

            # TODO checks on parent keys
            parent = s.get_reg_key().get_parent_key()
            while parent and parent.get_sd():
                # Untrusted user owns parent directory
                if not parent.get_sd().get_owner().is_trusted():
                    report.get_by_id("WPC041").add_supporting_data('service_regkey_parent_untrusted_ownership', [s, parent])

                # Parent dir can have file perms changed
                fa = parent.get_issue_acl_for_perms(["WRITE_OWNER", "WRITE_DAC"])
                if fa:
                    report.get_by_id("WPC042").add_supporting_data('service_regkey_parent_perms', [s, fa])

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
                            report.get_by_id("WPC043").add_supporting_data('service_regkey_parent_grandparent_write_perms', [s, fa_parent, fa_grandparent])

                parent = parent.get_parent_key()

        # Check that the binary name is properly quoted
        if str(s.get_exe_path_clean()).find(" ") > 0: # clean path contains a space
            if str(s.get_exe_path()).find(str('"' + s.get_exe_path_clean()) + '"') < 0: # TODO need regexp.  Could get false positive from this.
                report.get_by_id("WPC051").add_supporting_data('service_info', [s])

        #
        # Examine executable for service
        #
        if s.get_exe_file() and s.get_exe_file().get_sd():

            # Examine parent directories
            parent = s.get_exe_file().get_parent_dir()
            while parent and parent.get_sd():
                # Untrusted user owns parent directory
                if not parent.get_sd().get_owner().is_trusted():
                    report.get_by_id("WPC033").add_supporting_data('service_exe_parent_dir_untrusted_ownership', [s, parent])

                # Parent dir can have file perms changed
                fa = parent.get_file_acl_for_perms(["WRITE_OWNER", "WRITE_DAC"])
                if fa:
                    report.get_by_id("WPC032").add_supporting_data('service_exe_parent_dir_perms', [s, fa])

                # Child allows itself to be delete, parent allows it to be replaced
                fa_parent = parent.get_file_acl_for_perms(["DELETE"])
                if fa_parent:
                    grandparent = parent.get_parent_dir()
                    if grandparent and grandparent.get_sd():
                        fa_grandparent = grandparent.get_file_acl_for_perms(["FILE_ADD_SUBFOLDER"])
                        if fa_grandparent:
                            report.get_by_id("WPC031").add_supporting_data('service_exe_parent_grandparent_write_perms', [s, fa_parent, fa_grandparent])

                # Parent allows child directory to be deleted and replaced
                grandparent = parent.get_parent_dir()
                if grandparent and grandparent.get_sd():
                    fa = grandparent.get_file_acl_for_perms(["FILE_DELETE_CHILD", "FILE_ADD_SUBFOLDER"])
                    if fa:
                        report.get_by_id("WPC030").add_supporting_data('service_exe_parent_dir_perms', [s, fa])

                parent = parent.get_parent_dir()

            # Untrusted user owns exe
            if not s.get_exe_file().get_sd().get_owner().is_trusted():
                report.get_by_id("WPC029").add_supporting_data('service_exe_owner', [s])

            # Check if exe can be appended to
            fa = s.get_exe_file().get_file_acl_for_perms(["FILE_APPEND_DATA"])
            if fa:
                report.get_by_id("WPC027").add_supporting_data('service_exe_write_perms', [s, fa])

            # Check if exe can be deleted and perhaps replaced
            fa = s.get_exe_file().get_file_acl_for_perms(["DELETE"])
            if fa:
                # File can be delete (DoS issue)
                report.get_by_id("WPC026").add_supporting_data('service_exe_write_perms', [s, fa])

                # File can be deleted and replaced (privesc issue)
                parent = s.get_exe_file().get_parent_dir()
                if parent and parent.get_sd():
                    fa_parent = parent.get_file_acl_for_perms(["FILE_ADD_FILE"])
                    if fa_parent:
                        report.get_by_id("WPC034").add_supporting_data('service_exe_file_parent_write_perms', [s, fa, fa_parent])

            # Check for file perms allowing overwrite
            fa = s.get_exe_file().get_file_acl_for_perms(["FILE_WRITE_DATA", "WRITE_OWNER", "WRITE_DAC"])
            if fa:
                report.get_by_id("WPC028").add_supporting_data('service_exe_write_perms', [s, fa])

            # TODO write_file on a dir containing an exe might allow a dll to be added
        else:
            if not s.get_exe_file():
                report.get_by_id("WPC062").add_supporting_data('service_no_exe', [s])

        #
        # Examine security descriptor for service
        #
        if s.get_sd():

            # TODO all mine are owned by SYSTEM.  Maybe this issue can never occur!?
            if not s.get_sd().get_owner().is_trusted():
                report.get_by_id("WPC025").add_supporting_data('principals_with_service_ownership', [s, s.get_sd().get_owner()])

            # SERVICE_START
            for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["SERVICE_START"]).get_aces():
                report.get_by_id("WPC018").add_supporting_data('principals_with_service_perm', [s, a.get_principal()])

            # SERVICE_STOP
            for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["SERVICE_STOP"]).get_aces():
                report.get_by_id("WPC019").add_supporting_data('principals_with_service_perm', [s, a.get_principal()])

            # SERVICE_PAUSE_CONTINUE
            for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["SERVICE_PAUSE_CONTINUE"]).get_aces():
                report.get_by_id("WPC020").add_supporting_data('principals_with_service_perm', [s, a.get_principal()])

            # SERVICE_CHANGE_CONFIG
            for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["SERVICE_CHANGE_CONFIG"]).get_aces():
                report.get_by_id("WPC021").add_supporting_data('principals_with_service_perm', [s, a.get_principal()])

            # DELETE
            for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["DELETE"]).get_aces():
                report.get_by_id("WPC022").add_supporting_data('principals_with_service_perm', [s, a.get_principal()])

            # WRITE_DAC
            for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["WRITE_DAC"]).get_aces():
                report.get_by_id("WPC023").add_supporting_data('principals_with_service_perm', [s, a.get_principal()])

            # WRITE_OWNER
            for a in s.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["WRITE_OWNER"]).get_aces():
                report.get_by_id("WPC024").add_supporting_data('principals_with_service_perm', [s, a.get_principal()])


def csv_registry(report):
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

def audit_scheduled_tasks(report):
    try:
        content = subprocess.check_output("schtasks /query /xml", stderr = open(os.devnull, 'w'))
    except:
        print "[E] Can't run schtasks.  Doesn't work < Vista.  Skipping."
        return 0
    
    chunks = content.split("<!-- ")
    
    count = 0
    for chunk in chunks:
        count = count + 1
        if count == 1:
            continue # skip first chunk
    
        m = re.search("(.*) -->(.*)", chunk, re.MULTILINE | re.DOTALL)
        name = m.group(1)
        xml_string = m.group(2).lstrip()
        xml_string = xml_string.replace("UTF-16", "UTF-8")
        xml_string = xml_string.replace("</Tasks>", "")
        # print "xml: %s" % xml_string
        root = objectify.fromstring(xml_string)
        
        exec_command = "<none>"
        exec_args = "<none>"
        try: 
            exec_command = root.Actions.Exec.Command
            exec_args = root.Actions.Exec.Arguments
        except:
            pass
            
        enabled = 0
        try: 
            for trigger in root.Triggers.getchildren():
                #print "trigger tag: %s" % trigger.tag
                if trigger.Enabled.text == "true":
                    enabled = 1
        except:
            pass
            
        runas_user = "<none>"
        #runas_group = "<none>"
        try:
            runas_user = root.Principals.Principal.UserId
        except:
            runas_user = root.Principals.Principal.GroupId
        if enabled and exec_command != "<none>":
            print "------ %s -------" % name
            print "runas user: %s" % runas_user
            #print "runas group: %s" % runas_group
            print "exec command: %s" % exec_command
            exec_command = wpc.utils.env_expand(exec_command)
            print "exec command2: %s" % exec_command
            f = File(exec_command)
            if f.is_replaceable():
                print "[D] Weak perms for: %s" % f.get_name()
                for a in f.get_dangerous_aces():
                    report.get_by_id("WPC120").add_supporting_data('scheduled_task_exe_perms', [name, f, a])
            print "exec args: %s" % exec_args
            print


def audit_registry(report):

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
                        # print "[D] regkey: %s, file: %s" % (r.get_name() + "\\" + v, f.get_name())
                        if not f.exists():
                            f = wpc.utils.find_in_path(f)

                        if f and f.is_replaceable():
                            name = s.get_name().split("\\")[-1]
                            report.get_by_id(check_id).add_supporting_data('regkey_ref_replacable_file', [check_type, name, clsid, f, s])

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
                        report.get_by_id(issueid).add_supporting_data('regkey_ref_file', [rk, v, f])

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
                        report.get_by_id("WPC060").add_supporting_data('regkey_ref_file', [r, v, f])

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
                        report.get_by_id("WPC061").add_supporting_data('regkey_ref_file', [s, v, f])

    for key_string in wpc.conf.reg_paths:
        #parts = key_string.split("\\")
        #hive = parts[0]
        #key_string = "\\".join(parts[1:])

        r = regkey(key_string)

        if r.get_sd():

            # Check owner
            if not r.get_sd().get_owner().is_trusted():
                report.get_by_id("WPC046").add_supporting_data('regkey_program_untrusted_ownership', [r])

            # Untrusted users can change permissions
            acl = r.get_issue_acl_for_perms(["WRITE_OWNER", "WRITE_DAC"])
            if acl:
                report.get_by_id("WPC047").add_supporting_data('regkey_perms', [r, acl])

#            "KEY_SET_VALUE", # GUI "Set Value".  Required to create, delete, or set a registry value.
            acl = r.get_issue_acl_for_perms(["KEY_SET_VALUE"])
            if acl:
                report.get_by_id("WPC048").add_supporting_data('regkey_perms', [r, acl])

#            "KEY_CREATE_LINK", # GUI "Create Link".  Reserved for system use.
            acl = r.get_issue_acl_for_perms(["KEY_CREATE_LINK", "KEY_CREATE_SUB_KEY"])
            if acl:
                report.get_by_id("WPC049").add_supporting_data('regkey_perms', [r, acl])

#            "DELETE", # GUI "Delete"
            acl = r.get_issue_acl_for_perms(["DELETE"])
            if acl:
                report.get_by_id("WPC050").add_supporting_data('regkey_perms', [r, acl])

    print "[-] Walking registry (very slow: probably 15 mins - 1 hour)"
    for r in regkey('HKLM').get_all_subkeys():
        #print "[D] Processing: %s" % r.get_name()
        sd = r.get_sd()
        if sd:
            set_value_aces = sd.get_acelist().get_untrusted().get_aces_with_perms(["KEY_SET_VALUE"]).get_aces()
            #aces = r.get_dangerous_aces()
            if set_value_aces:
                for v in r.get_values():
                    #for a in set_value_aces:
                    #   for line in a.as_tab_delim3(r.get_name(), v, r.get_value(v)):
                    #        print line
                    if wpc.utils.looks_like_executable(r.get_value(v)):
                        for a in set_value_aces:
                            report.get_by_id("WPC115").add_supporting_data('regkey_value_data_perms', [r, v, repr(r.get_value(v)), a])
                    if wpc.utils.looks_like_path(r.get_value(v)):
                        for a in set_value_aces:
                            report.get_by_id("WPC116").add_supporting_data('regkey_value_data_perms', [r, v, repr(r.get_value(v)), a])
                    if wpc.utils.looks_like_registry_path(r.get_value(v)):
                        for a in set_value_aces:
                            report.get_by_id("WPC117").add_supporting_data('regkey_value_data_perms', [r, v, repr(r.get_value(v)), a])
                    if wpc.utils.looks_like_ip_address(r.get_value(v)):
                        for a in set_value_aces:
                            report.get_by_id("WPC118").add_supporting_data('regkey_value_data_perms', [r, v, repr(r.get_value(v)), a])
                    if wpc.utils.looks_like_user(r.get_value(v)):
                        for a in set_value_aces:
                            report.get_by_id("WPC119").add_supporting_data('regkey_value_data_perms', [r, v, repr(r.get_value(v)), a])


# Gather info about files and directories
def audit_program_files(report):
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
                    report.get_by_id("WPC001").add_supporting_data('writable_dirs', [f, ace])
                elif f.is_file():
                    report.get_by_id("WPC001").add_supporting_data('writable_progs', [f, ace])    
                else:
                    print "[E] Ignoring thing that isn't file or directory: " + f.get_name()

def dump_all_files(report):
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
#            if count > 1000:
#                exit(1)
            for ace in aces:
                for p in ace.get_perms():
                    print "%s\t%s\t%s\t%s\t%s" % (f.get_type(), f.get_name(), ace.get_type(), ace.get_principal().get_fq_name(), p)
#                if f.is_dir():
#                    report.get_by_id("WPC001").add_supporting_data('writable_dirs', [f, ace])
#                elif f.is_file():
#                    report.get_by_id("WPC001").add_supporting_data('writable_progs', [f, ace])    
#                else:
#                    print "[E] Ignoring thing that isn't file or directory: " + f.get_name()

            #f.clearmem() # memory leak

def audit_paths(report):
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
    audit_path_for_issue(report, wpc.utils.get_system_path(), "WPC013")

    print "[-] Checking current user's path"
    audit_path_for_issue(report, os.environ["PATH"], "WPC014")


def audit_path_for_issue(report, mypath, issueid):
    dirs = set(mypath.split(';'))
    exts = wpc.conf.executable_file_extensions
    for dir in dirs:
        weak_flag = 0
        d = File(dir)
        aces = d.get_dangerous_aces()
        for ace in aces:
            report.get_by_id(issueid).add_supporting_data('writable_dirs', [d, ace])

        for ext in exts:
            for myfile in glob.glob(dir + '\*.' + ext):
                f = File(myfile)
                aces = f.get_dangerous_aces()
                for ace in aces:
                    report.get_by_id(issueid).add_supporting_data('writable_progs', [f, ace])

        # TODO properly check perms with is_replaceable


def printline(message):
    print "\n============ %s ============" % message

def section(message):
    print "\n[+] Running: %s" % message
# ------------------------ Main Code Starts Here ---------------------

# Parse command line arguments
options = parseOptions()

# Initialise WPC
# TODO be able to enable/disable caching
wpc.utils.init(options)

# Object to hold all the issues we find
report = report()
wpc.utils.populate_scaninfo(report)
issues = report.get_issues()

printline("Starting Audit")

# Dump raw data if required
if options.dump_mode:
    section("dump_misc_checks")
    dump_misc_checks(issues)

    if options.do_all or options.do_paths:
        section("dump_paths")
        dump_paths(issues)

    if options.do_allfiles:
        section("dump_all_files")
        dump_all_files(issues)

    if options.do_all or options.do_eventlogs:
        section("dump_eventlogs")
        dump_eventlogs(issues)

    if options.do_all or options.do_shares:
        section("dump_shares")
        dump_shares(issues)

    if options.do_all or options.patchfile:
        section("dump_patches")
        dump_patches(issues)

    if options.do_all or options.do_loggedin:
        section("dump_loggedin")
        dump_loggedin(issues)

    if options.do_all or options.do_services:
        section("dump_services")
        dump_services(issues)

    if options.do_all or options.do_drivers:
        section("dump_drivers")
        dump_drivers(issues)

    if options.do_all or options.do_drives:
        section("dump_drives")
        dump_drives(issues)

    if options.do_all or options.do_processes:
        section("dump_processes")
        dump_processes(issues)

    if options.do_all or options.do_program_files:
        section("dump_program_files")
        dump_program_files(issues)

    if options.do_all or options.do_registry:
        section("dump_registry")
        dump_registry(issues)

    if options.do_all or options.do_reg_keys:
        section("dump_reg_keys")
        dump_reg_keys(issues)

    if options.do_all or options.do_users:
        section("dump_users")
        dump_users(issues, options.get_privs)

    if options.do_all or options.do_groups:
        section("dump_groups")
        dump_groups(issues, options.get_privs)

    if options.do_all or options.get_modals:
        section("dump_user_modals")
        dump_user_modals(issues)

# Identify security issues
if options.audit_mode:
    section("audit_misc_checks")
    try:
        audit_misc_checks(issues)
    except:
        pass

    if options.do_all or options.do_paths:
        section("audit_paths")
        try:
            audit_paths(issues)
        except:
            pass

    if options.do_all or options.do_eventlogs:
        section("audit_eventlogs")
        try:
            audit_eventlogs(issues)
        except:
            pass

    if options.do_all or options.do_shares:
        section("audit_shares")
        try:
            audit_shares(issues)
        except:
            pass

    if options.do_all or options.patchfile:
        section("audit_patches")
        try:
            audit_patches(issues)
        except:
            pass

    if options.do_all or options.do_loggedin:
        section("audit_loggedin")
        try:
            audit_loggedin(issues)
        except:
            pass

    if options.do_all or options.do_services:
        section("audit_services")
        try:
            audit_services(issues)
        except:
            pass

    if options.do_all or options.do_drivers:
        section("audit_drivers")
        try:
            audit_drivers(issues)
        except:
            pass

    if options.do_all or options.do_drives:
        section("audit_drives")
        try:
            audit_drives(issues)
        except:
            pass

    if options.do_all or options.do_processes:
        section("audit_processes")
        try:
            audit_processes(issues)
        except:
            pass

    if options.do_all or options.do_program_files:
        section("audit_program_files")
        try:
            audit_program_files(issues)
        except:
            pass

    if options.do_all or options.do_registry:
        section("audit_registry")
        try:
            audit_registry(issues)
        except:
            pass

    if options.do_all or options.do_scheduled_tasks:
        section("audit_scheduled_tasks")
        try:
            audit_scheduled_tasks(issues)
        except:
            pass

    if options.do_all or options.do_reg_keys:
        section("audit_reg_keys")
        try:
            audit_reg_keys(issues)
        except:
            pass

    if options.do_all or options.do_users:
        section("audit_users")
        try:
            audit_users(issues)
        except:
            pass



    if options.do_all or options.do_groups:
        section("audit_groups")
        try:
            audit_groups(issues)
        except:
            pass

    if options.report_file_stem:
        printline("Audit Complete")
        print

        # Don't expose XML to users as format will change shortly
        # filename = "%s.xml" % options.report_file_stem
        # print "[+] Saving report file %s" % filename
        # f = open(filename, 'w')
        # f.write(report.as_xml_string())
        # f.close()

        filename = "%s.txt" % options.report_file_stem
        print "[+] Saving report file %s" % filename
        f = open(filename, 'w')
        f.write(report.as_text())
        f.close()

        filename = "%s.html" % options.report_file_stem
        print "[+] Saving report file %s" % filename
        f = open(filename, 'w')
        f.write(report.as_html())
        f.close()

    #wpc.conf.cache.print_stats()
