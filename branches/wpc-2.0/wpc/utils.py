# Not a class
# Just a collection of useful subs
from wpc.cache import cache
from wpc.file import file as File
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
k32 = ctypes.windll.kernel32
wow64 = ctypes.c_long(0)
on64bitwindows = 1


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
    define_trusted_principals()

    # Use the crendentials supplied (OK to call if no creds were supplied)
    impersonate(options.remote_user, options.remote_pass, options.remote_domain)


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
    # Try to open file and ingore the result.  This gets win32security loaded and working.
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
    # Need to wrap in a try because the following call will error on 32-bit windows
    try:
        k32.Wow64DisableWow64FsRedirection(ctypes.byref(wow64))
        wpc.conf.on64bitwindows = 1
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
def define_trusted_principals():
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

    for t in wpc.conf.trusted_principals_fq:
        try:
            sid, name, i = win32security.LookupAccountName(wpc.conf.remote_server, t)
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

    print "Considering these users to be trusted:"
    for p in wpc.conf.trusted_principals:
        print "* " + p.get_fq_name()
    print


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
    return re_env.sub(expander, s)


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
    report.add_info_item('hostname', socket.gethostname())
    report.add_info_item('datetime', datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
    report.add_info_item('version', wpc.utils.get_version())
    report.add_info_item('user', os.environ['USERDOMAIN'] + "\\" + os.environ['USERNAME'])
    report.add_info_item('domain', win32api.GetDomainName())
    ver_list = win32api.GetVersionEx(1)

    try:
        report.add_info_item('ipaddress', ",".join(socket.gethostbyname_ex(socket.gethostname())[2]))  # have to do this before Wow64DisableWow64FsRedirection
    except:
        report.add_info_item('ipaddress', "<unknown>")  # have to do this before Wow64DisableWow64FsRedirection
        
    os_ver = str(ver_list[0]) + "." + str(ver_list[1])
    # version numbers from http://msdn.microsoft.com/en-us/library/ms724832(VS.85).aspx
    if os_ver == "4.0":
        os_str = "Windows NT"
    if os_ver == "5.0":
        os_str = "Windows 2000"
    if os_ver == "5.1":
        os_str = "Windows XP"
    if os_ver == "5.2":
        os_str = "Windows 2003"
    if os_ver == "6.0":
        os_str = "Windows Vista"
    if os_ver == "6.0":
        os_str = "Windows 2008"
    if os_ver == "6.1":
        os_str = "Windows 2008 R2"
    if os_ver == "6.1":
        os_str = "Windows 7"

    report.add_info_item('os', os_str)
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
    subkeys = win32api.RegEnumKeyEx(keyh)
    for subkey in subkeys:
        try:
            subkeyh = win32api.RegOpenKeyEx(keyh, subkey[0] + "\\Environment" , 0, win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE | win32con.KEY_READ)
        except:
            pass
        else:
            try:
                path, type = win32api.RegQueryValueEx(subkeyh, "PATH")
                try:
                    user_sid  = win32security.ConvertStringSidToSid(subkey[0])
                except:
                    print "WARNING: Can't convert sid %s to name.  Skipping." % subkey[0]
                    continue

                paths.append(user(user_sid), path)
            except:
                pass
    return paths