# Not a class
# Just a collection of useful subs
from wpc.cache import cache
from wpc.file import file as File
from wpc.process import process
from wpc.group import group as Group
from wpc.principal import principal
from wpc.regkey import regkey
from wpc.user import user
import ctypes
import ntsecuritycon
import os
import re
import win32api
import win32con
import win32net
import win32security
import wpc.conf
import string
import sys
import win32api
k32 = ctypes.windll.kernel32
wow64 = ctypes.c_long(0)
 

# There some strange stuff that we need to do in order
# We hide it all in here
#
# args:
#   remote_server can IP be None (should be None if on localhost)
def init(options):
    # Print banner with version and URL
#    print_banner()

    # Use some libs.  This will malfunction if we don't use them BEFORE we disable WOW64.
    load_libs()

    # Disable WOW64
    disable_wow64()

    # Get privs that make the program work better
    # - only helpful if we're admin
    get_extra_privs()

    # Set remote server - needed for sid resolution before we call wpc.* code
    wpc.conf.remote_server = options.remote_host

    # Create cache object to cache SID lookups and other data
    # This is (or should) be used by many wpc.* classes
    wpc.conf.cache = cache()

    # Which permissions do we NOT care about? == who do we trust?
    define_trusted_principals(options)

    # Use the crendentials supplied (OK to call if no creds were supplied)
    impersonate(options.remote_user, options.remote_pass, options.remote_domain)
    
    # calculate severity of issues from impact and ease
    max_impact = 5
    max_ease = 5
    for i in wpc.conf.issue_template.keys():
        impact = 0
        ease = 0
        #print wpc.conf.issue_template[i]
        if wpc.conf.issue_template[i]['impact']:
            impact = wpc.conf.issue_template[i]['impact']
        if wpc.conf.issue_template[i]['ease']:
            ease = wpc.conf.issue_template[i]['ease']
        severity = 100 * impact * ease / (max_impact * max_ease)
        #print "[D] setting severity of %s to %s" % (i, severity)
        wpc.conf.issue_template[i]['severity'] = severity
    

def tab_line(*fields):
    return "\t".join(map(str, fields))


def get_banner():
    return "windows-privesc-check v%s (http://pentestmonkey.net/windows-privesc-check)\n" % get_version()


def print_banner():
    print get_banner()


def get_version():
    wpc.conf.version = "2.0" 
    svnversion = "$Revision$"  # Don't change this line.  Auto-updated.
    svnnum = re.sub('[^0-9]', '', svnversion)
    if svnnum:
        wpc.conf.version = wpc.conf.version + "svn" + svnnum

    return wpc.conf.version


# If we're admin then we assign ourselves some extra privs
def get_extra_privs():
    # Try to give ourselves some extra privs (only works if we're admin):
    # SeBackupPrivilege   - so we can read anything
    # SeDebugPrivilege    - so we can find out about other processes (otherwise OpenProcess will fail for some)
    # SeSecurityPrivilege - ??? what does this do?

    # Problem: Vista+ support "Protected" processes, e.g. audiodg.exe.  We can't see info about these.
    # Interesting post on why Protected Process aren't really secure anyway: http://www.alex-ionescu.com/?p=34

    th = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
    privs = win32security.GetTokenInformation(th, ntsecuritycon.TokenPrivileges)
    newprivs = []
    for privtuple in privs:
        if privtuple[0] == win32security.LookupPrivilegeValue(wpc.conf.remote_server, "SeBackupPrivilege") or privtuple[0] == win32security.LookupPrivilegeValue(wpc.conf.remote_server, "SeDebugPrivilege") or privtuple[0] == win32security.LookupPrivilegeValue(wpc.conf.remote_server, "SeSecurityPrivilege"):
            # print "Added privilege " + str(privtuple[0])
            # privtuple[1] = 2 # tuples are immutable.  WHY?!
            newprivs.append((privtuple[0], 2))  # SE_PRIVILEGE_ENABLED
        else:
            newprivs.append((privtuple[0], privtuple[1]))

    # Adjust privs
    privs = tuple(newprivs)
    str(win32security.AdjustTokenPrivileges(th, False, privs))


# Give ourselves all the privs available in our access token
def get_all_privs(th):
    privs = win32security.GetTokenInformation(th, ntsecuritycon.TokenPrivileges)
    for privtuple in privs:
        privs2 = win32security.GetTokenInformation(th, ntsecuritycon.TokenPrivileges)
        newprivs = []
        for privtuple2 in privs2:
            if privtuple2[0] == privtuple[0]:
                newprivs.append((privtuple2[0], 2))  # SE_PRIVILEGE_ENABLED
            else:
                newprivs.append((privtuple2[0], privtuple2[1]))

        # Adjust privs
        privs3 = tuple(newprivs)
        win32security.AdjustTokenPrivileges(th, False, privs3)


FILTER=''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
def dump(src, length = 8):
    # Hex dump code from
    # http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/142812

    N = 0
    result = ''
    while src:
        s, src = src[:length], src[length:]
        hexa = ' '.join(["%02X" % ord(x) for x in s])
        su = s
        uni_string = ''
        for n in range(0, len(su) / 2):
            if su[n * 2 + 1] == "\0":
                uni_string += unicode(su[n * 2:n * 2 + 1], errors = 'ignore')
            else:
                uni_string += '?'
        s = s.translate(FILTER)
        result += "%04X %-*s%-16s %s\n" % (N, length * 3, hexa, s, uni_string)
        N += length
    return result


def load_libs():
    # Load win32security
    #
    # Try to open file and ignore the result.  This gets win32security loaded and working.
    # We can then turn off WOW64 and call repeatedly.  If we turn off WOW64 first, 
    # win32security will fail to work properly.
    try:
        sd = win32security.GetNamedSecurityInfo(
            ".",
            win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
        )
    except:
        # nothing
        pass

    # Load win32net
    #
    # NetLocalGroupEnum fails with like under Windows 7 64-bit, but not XP 32-bit:
    # pywintypes.error: (127, 'NetLocalGroupEnum', 'The specified procedure could not be found.')
    dummy = win32net.NetLocalGroupEnum(None, 0, 0, 1000)


def disable_wow64():
    # Disable WOW64 - we WANT to see 32-bit areas of the filesystem
    #
    # Need to wrap in a try because the following call may error on 32-bit windows
    try:
        if k32.Wow64DisableWow64FsRedirection(ctypes.byref(wow64)):
            wpc.conf.on64bitwindows = 1
        else:
            wpc.conf.on64bitwindows = 0
    except:
        wpc.conf.on64bitwindows = 0

    # WOW64 is now disabled, so we can read file permissions without Windows redirecting us from system32 to syswow64


def enable_wow64():
    # When we interrogate a 32-bit process we need to see the filesystem
    # the same we it does.  In this case we'll need to enable wow64
    try:
        k32.Wow64DisableWow64FsRedirection(ctypes.byref(wow64))
    except:
        pass

# We don't report issues about permissions being held by trusted users or groups
# hard-coded users and groups (wpc.conf.trusted_principals_fq[]) done
# user-defined users and groups (--ignore) TODO
# hard-coded SIDs (S-1-5-32-549 is common) TODO
# user-defined SIDs (--ignore) TODO
# SIDs which don't resolve (probably only want to ignore local SIDs, not domain SIDs) TODO
# Group that are empty (e.g. Power Users should normally be ignored because it's empty) TODO - make it an option
# Ignore everything that the current user isn't a member of (for privescing) TODO
def define_trusted_principals(options):
    exploitable_by_fq = []
    ignore_principals = []
    if options.exploitable_by_list:
        exploitable_by_fq = options.exploitable_by_list
    if options.exploitable_by_file:
        try:
            exploitable_by_fq = exploitable_by_fq + [line.strip() for line in open(options.exploitable_by_file)]
        except:
            print "[E] Error reading from file %s" % options.exploitablebyfile
            sys.exit()
    if options.ignore_principal_list:
        ignore_principals = options.ignore_principal_list
    if options.ignore_principal_file:
        try:
            ignore_principals = ignore_principals + [line.strip() for line in open(options.ignoreprincipalfile)]
        except:
            print "[E] Error reading from file %s" % options.ignoreprincipalfile
            sys.exit()
            
    # examine token, populate exploitable_by
    if options.exploitable_by_me:
        try:
            p = process(os.getpid())
            wpc.conf.exploitable_by.append(p.get_token().get_token_owner())
            for g in p.get_token().get_token_groups():
                if "|".join(g[1]).find("USE_FOR_DENY_ONLY") == -1:
                    wpc.conf.exploitable_by.append(g[0])
        except:
            print "[E] Problem examining access token of current process"
            sys.exit()
    
    # check each of the supplied users in exploitable_by and exploitable_by resolve
    
    if exploitable_by_fq or wpc.conf.exploitable_by:
        wpc.conf.privesc_mode = "exploitable_by"
        for t in exploitable_by_fq:
            try:
                sid, _, _ = win32security.LookupAccountName(wpc.conf.remote_server, t)
                if sid:
                    p = principal(sid)
                    #print "Trusted: %s (%s) [%s]" % (p.get_fq_name(), p.get_type_string(), p.is_group_type())
                    #print "[D] Added trusted principal %s.  is group? %s" % (p.get_fq_name(), p.is_group_type())
                    if p.is_group_type():
                        p = Group(p.get_sid())
                    #    for m in p.get_members():
                    #        print "Member: %s" % m.get_fq_name()
                    else:
                        p = user(p.get_sid())
                    #    print p.get_groups()
    
                    wpc.conf.exploitable_by.append(p)
    
                else:
                    print "[E] can't look up sid for " + t
            except:
                pass
    
        print "Only reporting privesc issues for these users/groups:"
        for p in wpc.conf.exploitable_by:
            print "* " + p.get_fq_name()        
        return
    else:
        wpc.conf.privesc_mode = "report_untrusted"
        
    # if user has specified list of trusted users, use only their list
    if ignore_principals:
        if options.ignorenoone:
            wpc.conf.trusted_principals_fq = []
        wpc.conf.trusted_principals_fq = wpc.conf.trusted_principals_fq + ignore_principals
    else:
        # otherwise the user has not specified a list of trusted users.  we intelligently tweak the list.
        # Ignore "NT AUTHORITY\TERMINAL SERVER USER" if HKLM\System\CurrentControlSet\Control\Terminal Server\TSUserEnabled = 0 or doesn't exist
        # See http://support.microsoft.com/kb/238965 for details
        r = regkey(r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server")
    
        if r.is_present():
            v = r.get_value("TSUserEnabled")
            if v is None:
                print "[i] TSUserEnabled registry value is absent. Excluding TERMINAL SERVER USER"
            elif v != 0:
                print "[i] TSUserEnabled registry value is %s. Including TERMINAL SERVER USER" % v
                wpc.conf.trusted_principals_fq.append("NT AUTHORITY\TERMINAL SERVER USER")
            else:
                print "[i] TSUserEnabled registry value is 0. Excluding TERMINAL SERVER USER"
        else:
            print "[i] TSUserEnabled registry key is absent. Excluding TERMINAL SERVER USER"
        print

        # TODO we only want to ignore this if it doesn't resolve
        try:
            # Server Operators group
            #print "[D] converting string sid"
            #print "%s" % win32security.ConvertStringSidToSid("S-1-5-32-549")
            p = Group(win32security.ConvertStringSidToSid("S-1-5-32-549"))
    
        except:
            wpc.conf.trusted_principals.append(p)
    
        # TODO this always ignored power users.  not what we want.
        # only want to ignore when group doesn't exist.
        try:
            p = Group(win32security.ConvertStringSidToSid("S-1-5-32-547"))
            wpc.conf.trusted_principals.append(p)
        except:
            pass
    
    # populate wpc.conf.trusted_principals with the objects corresponding to trusted_principals_fq
    for t in wpc.conf.trusted_principals_fq:
        try:
            sid, _, _ = win32security.LookupAccountName(wpc.conf.remote_server, t)
            if sid:
                p = principal(sid)
                #print "Trusted: %s (%s) [%s]" % (p.get_fq_name(), p.get_type_string(), p.is_group_type())
                #print "[D] Added trusted principal %s.  is group? %s" % (p.get_fq_name(), p.is_group_type())
                if p.is_group_type():
                    p = Group(p.get_sid())
                #    for m in p.get_members():
                #        print "Member: %s" % m.get_fq_name()
                else:
                    p = user(p.get_sid())
                #    print p.get_groups()

                wpc.conf.trusted_principals.append(p)

            else:
                print "[E] can't look up sid for " + t
        except:
            pass

    print "Considering these users to be trusted:"
    for p in wpc.conf.trusted_principals:
        print "* " + p.get_fq_name()
    print


def looks_like_executable(s):
    if s is None:
        return 0
    s = str(s) # doesn't work on int
    re_string = r'\.' + r'$|\.'.join(wpc.conf.executable_file_extensions) + r'$'  # '\.exe$|\.py$|\.svn-base$|\.com$|\.bat$|\.dll$'
    re_exe = re.compile(re_string, re.IGNORECASE)
    m = re_exe.match(s)
    if m is None:
        return 0
    return 1

def looks_like_path(s):
    if s is None:
        return 0
    s = str(s) # doesn't work on int
    re_string = r'^\\\\|^[a-z]:\\|%systemroot%|%systemdrive%'
    re_exe = re.compile(re_string, re.IGNORECASE)
    m = re_exe.match(s)
    if m is None:
        return 0
    return 1

def looks_like_registry_path(s):
    if s is None:
        return 0
    s = str(s) # doesn't work on int
    re_string = r'^SYSTEM\\'
    re_exe = re.compile(re_string, re.IGNORECASE)
    m = re_exe.match(s)
    if m is None:
        return 0
    return 1

def looks_like_ip_address(s):
    if s is None:
        return 0
    s = str(s) # doesn't work on int
    re_string = r'^d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    re_exe = re.compile(re_string, re.IGNORECASE)
    m = re_exe.match(s)
    if m is None:
        return 0
    return 1

def looks_like_user(s):
    if s is None:
        return 0
    s = str(s) # doesn't work on int
    re_string = r'^administrator|^system[^\\]|NT AUTHORITY\\|BUILTIN\\'
    re_exe = re.compile(re_string, re.IGNORECASE)
    m = re_exe.match(s)
    if m is None:
        return 0
    return 1

# Walk a directory tree, returning all matching files
#
# args:
#   dir         directory to descend
#   extensions  list of file entensions to return e.g. ('bat', 'exe', ...)
#   inc_dirs    whether to return dirs or not # TODO need option to only return dirs that contain files of interest
# TODO what if we pass a non-existent directory?
def dirwalk(directory, extensions, include_dirs):

    # Compile regular expression for file entension matching
    re_string = r'\.' + r'$|\.'.join(extensions)  # '\.exe$|\.py$|\.svn-base$|\.com$|\.bat$|\.dll$'
    re_exe = re.compile(re_string, re.IGNORECASE)

    for root, dirs, files in oswalk(directory):
            #print "root=%s, dirs=%s, files=%s" % (root, dirs, files)
            yield root

            for file in files:
                m = re_exe.search(file)
                if m is None:
                    continue
                else:
                    yield root + "\\" + file

            if include_dirs:
                for directory in dirs:
                    yield root + "\\" + directory

# Copy of os.walk with minor mod to detect reparse points
def oswalk(top, topdown=True, onerror=None, followlinks=False):
    from os.path import join, isdir, islink
    import errno
    error = None
    try:
        # Note that listdir and error are globals in this module due
        # to earlier import-*.
        names = os.listdir(top)
    except:
        return

    dirs, nondirs = [], []
    for name in names:
        if isdir(join(top, name)):
            dirs.append(name)
        else:
            nondirs.append(name)

    if topdown:
        yield top, dirs, nondirs
    for name in dirs:
        path = join(top, name)
        if followlinks or not is_reparse_point(path):
            for x in oswalk(path, topdown, onerror, followlinks):
                yield x
    if not topdown:
        yield top, dirs, nondirs

        
def is_reparse_point(d):
            try:
                attr = win32api.GetFileAttributes(d)
                # reparse point http://msdn.microsoft.com/en-us/library/windows/desktop/gg258117(v=vs.85).aspx
                if attr & 0x400:
                    print "[D] Is reparse point: %s" % d
                    return 1
            except:
                pass
            return 0


# arg s contains windows-style env vars like: %windir%\foo
def env_expand(s):
    re_env = re.compile(r'%\w+%')
    return re_env.sub(expander, str(s))


def find_in_path(f):
    f_str = f.get_name()
    for d in os.environ.get('PATH').split(';'):
        #print "[D] looking in path for %s" % d + "\\" + f_str
        if os.path.exists(d + "\\" + f_str):
            #print "[D] found in path %s" % d + "\\" + f_str
            return File(d + "\\" + f_str)
    return None


def lookup_files_for_clsid(clsid):
    results = []
    # Potentially intersting subkeys of clsids are listed here:
    # http://msdn.microsoft.com/en-us/library/windows/desktop/ms691424(v=vs.85).aspx

    for v in ("InprocServer", "InprocServer32", "LocalServer", "LocalServer32"):
        r = regkey("HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\" + clsid + "\\" + v)
        if r.is_present:
            d = r.get_value("")  # "(Default)" value
            if d:
                d = env_expand(d)
                results.append([r, v, File(d)])
#    else:
#        print "[i] Skipping non-existent clsid: %s" % r.get_name()

    return results


def expander(mo):
    return os.environ.get(mo.group()[1:-1], 'UNKNOWN')

def to_printable(s):
    try:
        if s is None:
            return None
        s = str(s)
    except:
        pass
    newstring = ""

    try:    
        for c in s:
            if c in string.printable:
                newstring = newstring + c
            else:
                newstring = newstring + "?"
        return newstring
    except:
        return "[WPC internal error parsing this string]"

def dequote(binary_dirty):
    # remove quotes and leading white space
    m = re.search('^[\s]*?"([^"]+)"', binary_dirty)
    if m and os.path.exists(m.group(1)):
        exe_path_clean = m.group(1)
        return exe_path_clean
    else:
        if m:
            binary_dirty = m.group(1)
            
    return binary_dirty
    
# Attempts to clean up strange looking file paths like:
#   \??\C:\WINDOWS\system32\csrss.exe
#   \SystemRoot\System32\smss.exe
def get_exe_path_clean(binary_dirty):
    exe_path_clean = None

    # remove quotes and leading white space
    m = re.search('^[\s]*?"([^"]+)"', binary_dirty)
    if m and os.path.exists(m.group(1)):
        exe_path_clean = m.group(1)
        return exe_path_clean
    else:
        if m:
            binary_dirty = m.group(1)

    # Paths for drivers are written in an odd way, so we regex them
    binary_dirty = binary_dirty.replace("\x00", "")
    re1 = re.compile(r'^\\systemroot', re.IGNORECASE)
    binary_dirty = re1.sub(os.getenv('SystemRoot'), binary_dirty)
    re2 = re.compile(r'^system32\\', re.IGNORECASE)
    binary_dirty = re2.sub(os.getenv('SystemRoot') + r'\\system32\\', binary_dirty)
    re2 = re.compile(r'^\\\?\?\\', re.IGNORECASE)
    binary_dirty = re2.sub('', binary_dirty)

    if os.path.exists(binary_dirty):
        exe_path_clean = binary_dirty
        return exe_path_clean

    chunks = binary_dirty.split(" ")
    candidate = ""
    for chunk in chunks:
        if candidate:
            candidate = candidate + " "
        candidate = candidate + chunk

        if os.path.exists(candidate) and os.path.isfile(candidate):
            exe_path_clean = candidate
            break

        if os.path.exists(candidate + ".exe") and os.path.isfile(candidate + ".exe"):
            exe_path_clean = candidate + ".exe"
            break

        if wpc.conf.on64bitwindows:
            candidate2 = candidate.replace("system32", "syswow64")
            if os.path.exists(candidate2) and os.path.isfile(candidate2):
                exe_path_clean = candidate2
                break

            if os.path.exists(candidate2 + ".exe") and os.path.isfile(candidate2 + ".exe"):
                exe_path_clean = candidate2 + ".exe"
                break
    return exe_path_clean


def impersonate(username, password, domain):
    if username:
        print "Using alternative credentials:"
        print "Username: " + str(username)
        print "Password: " + str(password)
        print "Domain:   " + str(domain)
        handle = win32security.LogonUser(username, domain, password, win32security.LOGON32_LOGON_NEW_CREDENTIALS, win32security.LOGON32_PROVIDER_WINNT50)
        win32security.ImpersonateLoggedOnUser(handle)
    else:
        print "[i] Running as current user.  No logon creds supplied (-u, -D, -p)."
    print

def populate_scaninfo(report):
    import socket
    import datetime
    
    report.add_info_item('privesc_mode', wpc.conf.privesc_mode)
    if wpc.conf.privesc_mode == "report_untrusted":
        report.add_info_item('exploitable_by', "N/A (running in report_untrusted mode)")
        trusted = []
        for t in wpc.conf.trusted_principals:
            trusted.append(t.get_fq_name())
        report.add_info_item('ignored_users', ",".join(trusted))
    elif wpc.conf.privesc_mode == "exploitable_by":
        report.add_info_item('ignored_users', "N/A (running in exploitable_by mode)")
        exploitable_by = []
        for e in wpc.conf.exploitable_by:
            exploitable_by.append(e.get_fq_name())
        report.add_info_item('exploitable_by', ",".join(exploitable_by))
        
    report.add_info_item('hostname', socket.gethostname())
    report.add_info_item('datetime', datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
    report.add_info_item('version', wpc.utils.get_version())
    report.add_info_item('user', os.environ['USERDOMAIN'] + "\\" + os.environ['USERNAME'])
    report.add_info_item('domain', win32api.GetDomainName())
    ver_list = win32api.GetVersionEx(1) # bug on windows 8.1  https://msdn.microsoft.com/en-us/library/windows/desktop/ms724451%28v=vs.85%29.aspx

    try:
        report.add_info_item('ipaddress', ",".join(socket.gethostbyname_ex(socket.gethostname())[2]))  # have to do this before Wow64DisableWow64FsRedirection
    except:
        report.add_info_item('ipaddress', "<unknown>")  # have to do this before Wow64DisableWow64FsRedirection

    major = ver_list[0]
    minor = ver_list[1]
    build = ver_list[2]
    prod_type = ver_list[8]

    # version numbers from http://msdn.microsoft.com/en-us/library/ms724832(VS.85).aspx
    os_name = {}
    os_name[4] = {}
    os_name[5] = {}
    os_name[6] = {}
    os_name[10] = {}
    os_name[4][0] = {}
    os_name[6][0] = {}
    os_name[5][0] = {}
    os_name[5][1] = {}
    os_name[5][2] = {}
    os_name[6][1] = {}
    os_name[6][2] = {}
    os_name[6][3] = {}
    os_name[6][4] = {}
    os_name[10][0] = {}
    os_name[4][0][3] = "Windows NT"
    os_name[5][0][3] = "Windows 2000"
    os_name[5][2][3] = "Windows 2003"
    os_name[6][0][3] = "Windows 2008"
    os_name[6][1][3] = "Windows 2008 R2"
    os_name[6][2][3] = "Windows 2012"
    os_name[6][3][3] = "Windows 2012 R2"
    os_name[5][1][1] = "Windows XP"
    os_name[6][0][1] = "Windows Vista"
    os_name[6][1][1] = "Windows 7"
    os_name[6][2][1] = "Windows 8"
    os_name[6][3][1] = "Windows 8.1"
    os_name[6][4][1] = "Windows 10 Preview"
    os_name[10][0][1] = "Windows 10"

    search_prod_type = prod_type
    if prod_type == 2: # domain controller
        search_prod_type = 3
    if major in os_name.keys() and minor in os_name[major].keys() and search_prod_type in os_name[major][minor].keys():
        os_str = os_name[major][minor][search_prod_type]
    else:
        os_str = "Unrecognised Windows version: %s.%s.%s (type: %s)" % (major, minor, build, prod_type)

    report.add_info_item('os', os_str)
    if prod_type == 2:
        report.add_info_item('is_domain_controller', "yes")
    else:
        report.add_info_item('is_domain_controller', "no")
    report.add_info_item('os_version', str(ver_list[0]) + "." + str(ver_list[1]) + "." + str(ver_list[2]) + " SP" + str(ver_list[5]))


def get_system_path():
    key_string = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    try:
        keyh = win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE, key_string , 0, win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE | win32con.KEY_READ)
    except:
        return None

    try:
        path, type = win32api.RegQueryValueEx(keyh, "PATH")
    except:
        return None

    return wpc.utils.env_expand(path)


def get_user_paths():
    try:
        keyh = win32api.RegOpenKeyEx(win32con.HKEY_USERS, None , 0, win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE | win32con.KEY_READ)
    except:
        return 0
    paths = []
    import pywintypes
    subkeys = win32api.RegEnumKeyEx(keyh)
    for subkey in subkeys:
            #print subkey
            try:
                subkeyh = win32api.RegOpenKeyEx(keyh, subkey[0] + "\\Environment" , 0, win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE | win32con.KEY_READ)
                path, type = win32api.RegQueryValueEx(subkeyh, "PATH")
                try:
                    user_sid  = win32security.ConvertStringSidToSid(subkey[0])
                except:
                    #print "WARNING: Can't convert sid %s to name.  Skipping." % subkey[0]
                    continue
                #print "subkey: %s" % subkey[0]
                paths.append([user(user_sid), path])
            except pywintypes.error as e:
                #print e
                pass
    return paths

def dump_options(options):
    print "[+] Runtime Options Dump"
    optdict = options.__dict__ 
    optdict["privesc_mode"] = wpc.conf.privesc_mode
    for k in sorted(optdict.keys()):
        if k == "dump_mode" and optdict[k] == True:
            print " mode: dump"
        if k == "dumptab_mode" and optdict[k] == True:
            print " mode: dumptab"
        if k == "audit_mode" and optdict[k] == True:
            print " mode: audit"
    for k in sorted(optdict.keys()):
        if k == "privesc_mode" or k.find("_mode") == -1:
            if k == "ignore_principal_list":
                print " %s: %s" % (k, wpc.conf.trusted_principals_fq)
            elif k == "exploitable_by_list":
                print " %s: %s" % (k, map(lambda g: g.get_fq_name(), wpc.conf.exploitable_by))
            elif k.find("interesting") != -1 and optdict['do_allfiles'] == False:
                pass
            elif k.find("exploitable_by") != -1 and optdict['privesc_mode'] != 'exploitable_by':
                pass
            elif k.find("get_") != -1 and optdict['audit_mode'] == True:
                pass
            else:
                print " %s: %s" % (k, optdict[k])
    

def print_major(message, *args):
    indent = 0
    if args:
        indent = args[0]
    print "%s[+] %s" % (" " * indent, message)
    

def printline(message):
    print "\n============ %s ============" % message

def section(message):
    print "\n[+] Running: %s" % message

# is v1 <= v2?  e.g. is 1.21.3 <= 1.2.3 (no in this case)
def version_less_than_or_equal_to(v1, v2):
    versions = [v1, v2]
    versions.sort(key=lambda s: map(int, s.split('.')))
    highest = versions[1]
    if v2 == highest:
        return 1
    return 0

def host_is_dc():
    return win32api.GetVersionEx(1)[8] == 2