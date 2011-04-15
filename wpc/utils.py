# Not a class
# Just a collection of useful subs
import os
import re
import ctypes
import win32net
import win32security
import wpc.conf
import win32api
import win32con
import ntsecuritycon
from wpc.principal import principal
from wpc.user import user
from wpc.group import group as Group
from wpc.cache import cache
k32 = ctypes.windll.kernel32
wow64 = ctypes.c_long( 0 )
on64bitwindows = 1

# There some strange stuff that we need to do in order
# We hide it all in here
#
# args:
#   remote_server can IP be None (should be None if on localhost)
def init(options):
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
	
	wpc.conf.version = "2.0"
	svnversion="$Revision$" # Don't change this line.  Auto-updated.
	svnnum=re.sub('[^0-9]', '', svnversion)
	if svnnum:
		wpc.conf.version = wpc.conf.version + "svn" + svnnum

	print "windows-privesc-check v%s (http://pentestmonkey.net/windows-privesc-check)\n" % wpc.conf.version

	# Which permissions do we NOT care about? == who do we trust?
	define_trusted_principals()
	
	# Use the crendentials supplied (OK to call if no creds were supplied)
	impersonate(options.remote_user, options.remote_pass, options.remote_domain)

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
			newprivs.append((privtuple[0], 2)) # SE_PRIVILEGE_ENABLED
		else:
			newprivs.append((privtuple[0], privtuple[1]))
				
	# Adjust privs
	privs = tuple(newprivs)
	str(win32security.AdjustTokenPrivileges(th, False , privs))

def load_libs():
	# Load win32security
	#
	# Try to open file and ingore the result.  This gets win32security loaded and working.
	# We can then turn off WOW64 and call repeatedly.  If we turn off WOW64 first, 
	# win32security will fail to work properly.
	try:
		sd = win32security.GetNamedSecurityInfo (
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
		k32.Wow64DisableWow64FsRedirection( ctypes.byref(wow64) )
		wpc.conf.on64bitwindows = 1
	except:
		wpc.conf.on64bitwindows = 0

	# WOW64 is now disabled, so we can read file permissions without Windows redirecting us from system32 to syswow64

def enabled_wow64():
	# When we interrogate a 32-bit process we need to see the filesystem
	# the same we it does.  In this case we'll need to enable wow64
	try:
		k32.Wow64DisableWow64FsRedirection( ctypes.byref(wow64) )
	except:
		pass

def define_trusted_principals():
	for t in wpc.conf.trusted_principals_fq:
	#for t in "x":
		#print t
		try:
			sid, name, i = win32security.LookupAccountName(wpc.conf.remote_server, t)
			if sid:
				p = principal(sid)
				#print "Trusted: %s (%s) [%s]" % (p.get_fq_name(), p.get_type_string(), p.is_group_type())
				if p.is_group_type():
					p = Group(p.get_sid())
				#	for m in p.get_members():
				#		print "Member: %s" % m.get_fq_name()
				else:
					p = user(p.get_sid())
				#	print p.get_groups()
					
				wpc.conf.trusted_principals.append(p)
				
			else:
				print "[E] can't look up sid for " + t
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
def dirwalk(dir, extensions, include_dirs):

	# Compile regular expression for file entension matching
	re_string = r'\.' + r'$|\.'.join(extensions) # '\.exe$|\.py$|\.svn-base$|\.com$|\.bat$|\.dll$'
	re_exe = re.compile(re_string, re.IGNORECASE)

	for root, dirs, files in os.walk(dir):
			#print "root=%s, dirs=%s, files=%s" % (root, dirs, files)
			yield root
			
			for file in files:
				m = re_exe.search(file)
				if m is None:
					continue
				else:
					yield root + "\\" + file
			
			if include_dirs:
				for dir in dirs:
					yield root + "\\" + dir

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
		handle = win32security.LogonUser( username, domain, password, win32security.LOGON32_LOGON_NEW_CREDENTIALS, win32security.LOGON32_PROVIDER_WINNT50 )
		win32security.ImpersonateLoggedOnUser( handle )
	else:
		print "Running as current user.  No logon creds supplied (-u, -D, -p)."
	print
	