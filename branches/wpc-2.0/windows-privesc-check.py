# TODO which of these don't we need to import?
from wpc.parseOptions import parseOptions
import profile
import ntsecuritycon
import win32ts
import win32api
import win32con
import win32security
import win32net
import wpc.conf
from wpc.users import users
from wpc.groups import groups
from wpc.shares import shares
from wpc.token import token
from wpc.cache import cache
from wpc.file import file as File
from wpc.files import files
from wpc.principal import principal
from wpc.group import group as Group
from wpc.user import user
from wpc.services import drivers
from wpc.report.issue import issue
from wpc.report.fileAcl import fileAcl
from wpc.services import services
from wpc.regkey import regkey
from wpc.processes import processes
from wpc.report.issues import issues
import glob
import sys
import os
import wpc.utils

# ---------------------- Define Subs ---------------------------

def dump_services(opts):
	for s in services().get_services():
		if opts.ignore_trusted:
			print s.untrusted_as_text()
		else:
			print s.as_text()

def dump_drivers(opts):		
	for d in drivers().get_services():
		if opts.ignore_trusted:
			print d.untrusted_as_text()
		else:
			print d.as_text()

def dump_processes(opts):	
	for p in processes().get_all():
		print p.as_text()
		
		# When listing DLLs for a process we need to see the filesystem like they do
		if p.is_wow64():
			k32.Wow64EnableWow64FsRedirection( ctypes.byref(wow64) )
			
		if p.get_exe():
			print "Security Descriptor for Exe File %s" % p.get_exe().get_name()
			if p.get_exe().get_sd():
				print p.get_exe().get_sd().as_text()
			else:
				print "[unknown]"
			
			for dll in p.get_dlls():
				print "\nSecurity Descriptor for DLL File %s" % dll.get_name()
				print dll.get_sd().as_text()

		if p.is_wow64():
			k32.Wow64DisableWow64FsRedirection( ctypes.byref(wow64) )
		
def dump_users(opts):
	print "[+] Dumping user list:"
	userlist = users()
	for u in userlist.get_all():
		print u.get_fq_name()
		
		if opts.get_privs:
			print "\n\t[+] Privileges of this user:"
			for priv in u.get_privs():
				print "\t%s" % priv

			print "\n\t[+] Privileges of this user + the groups it is in:"
			print "\t[!] Not implemented yet"

def dump_groups(opts):
	print "[+] Dumping group list:"
	grouplist = groups()
	for g in grouplist.get_all():
		print g.get_fq_name()
		
		if opts.get_members:
			print "\n\t[+] Members:"
			for m in g.get_members():
				print "\t%s" % m.get_fq_name()
				
		if opts.get_privs:
			print "\n\t[+] Privileges of this group:"
			for priv in g.get_privs():
				print "\t%s" % priv

			print "\n\t[+] Privileges of this group + the groups it is in:"
			print "\t[!] Not implemented yet"

def dump_registry(opts):
	print "[!] Registry dump option not implemented yet.  Sorry." # TODO

def audit_drivers(opts):
	print "[!] Driver audit option not implemented yet.  Sorry." # TODO

def audit_processes(opts):
	print "[!] Process audit option not implemented yet.  Sorry." # TODO

def audit_users(opts):
	print "[!] User audit option not implemented yet.  Sorry." # TODO
		
def audit_groups(opts):
	print "[!] Group audit option not implemented yet.  Sorry." # TODO
		
def audit_services(report):
	for s in services().get_services():
	
		#
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
				
#			"KEY_SET_VALUE", # GUI "Set Value".  Required to create, delete, or set a registry value.
			acl = s.get_reg_key().get_issue_acl_for_perms(["KEY_SET_VALUE"])
			if acl:
				report.get_by_id("WPC037").add_supporting_data('service_reg_perms', [s, acl])
				
#			"KEY_CREATE_LINK", # GUI "Create Link".  Reserved for system use.
			acl = s.get_reg_key().get_issue_acl_for_perms(["KEY_CREATE_LINK"])
			if acl:
				report.get_by_id("WPC038").add_supporting_data('service_reg_perms', [s, acl])
				
#			"KEY_CREATE_SUB_KEY", # GUI "Create subkey"
			acl = s.get_reg_key().get_issue_acl_for_perms(["KEY_CREATE_SUB_KEY"])
			if acl:
				report.get_by_id("WPC039").add_supporting_data('service_reg_perms', [s, acl])
				
#			"DELETE", # GUI "Delete"
			acl = s.get_reg_key().get_issue_acl_for_perms(["DELETE"])
			if acl:
				report.get_by_id("WPC040").add_supporting_data('service_reg_perms', [s, acl])
				
			# TODO walk sub keys looking for weak perms - not necessarily a problem, but could be interesting
			
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
			
		
		#
		# Examine executable for service
		#
		if s.get_exe_file() and s.get_exe_file().get_sd():
		
			# Examine parent directories
			parent = s.get_exe_file().get_parent_dir()
			while parent: # TODO and can get sd?
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
				report.get_by_id("WPC029").add_supporting_data('service_exe_write_perms', [s])
			
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

def audit_registry(report):
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
				
#			"KEY_SET_VALUE", # GUI "Set Value".  Required to create, delete, or set a registry value.
			acl = r.get_issue_acl_for_perms(["KEY_SET_VALUE"])
			if acl:
				report.get_by_id("WPC048").add_supporting_data('regkey_perms', [r, acl])
				
#			"KEY_CREATE_LINK", # GUI "Create Link".  Reserved for system use.
			acl = r.get_issue_acl_for_perms(["KEY_CREATE_LINK", "KEY_CREATE_SUB_KEY"])
			if acl:
				report.get_by_id("WPC049").add_supporting_data('regkey_perms', [r, acl])
	
#			"DELETE", # GUI "Delete"
			acl = r.get_issue_acl_for_perms(["DELETE"])
			if acl:
				report.get_by_id("WPC050").add_supporting_data('regkey_perms', [r, acl])
	
# Gather info about files and directories
def gather_file_info(file_info):
	# Record info about all directories
	include_dirs = 1
	
	# TODO how to set this automatically?
	prog_dirs = (r'C:\Program Files', r'C:\Program Files (x86)') # TODO why can't i have just one entry here?
	#prog_dirs = (r'C:\Program Files (x86)\adobe', r'C:\Program Files (x86)\adobe')
	
	for dir in prog_dirs:
		# Walk program files directories looking for executables
		# TODO allow wpc.conf.executable_file_extensions to be changed from command line
		for filename in wpc.utils.dirwalk(dir, wpc.conf.executable_file_extensions, include_dirs):
			#print "[D] Processing: " + filename
			file_info.add_by_name(filename)
			# TODO would it be helpful to add tags to files - e.g. executable, executable_dir, program_files, etc.?
			#      we might be able to do clever queries later
		
def analyse_file_info(file_info, report):
	for f in file_info.get_files():
		#print "[D] Analysing: " + f.get_name()
		a = f.get_dangerous_aces()
				
		if not a == []:
			if f.is_dir():
				report.get_by_id("WPC001").add_supporting_data('writable_dirs', fileAcl(f.get_name(), a))
			elif f.is_file():
				report.get_by_id("WPC001").add_supporting_data('writable_progs', fileAcl(f.get_name(), a))	
			else:
				print "[E] Ignoring thing that isn't file or directory: " + f.get_name()
	
def program_files(report):
	# Record info about all directories
	include_dirs = 1
	
	# TODO how to set this automatically?
	prog_dirs = (r'C:\Program Files', r'C:\Program Files (x86)') # TODO why can't i have just one entry here?
	#prog_dirs = (r'C:\Program Files (x86)\adobe', r'C:\Program Files (x86)\adobe')
	
	for dir in prog_dirs:
		# Walk program files directories looking for executables
		# TODO allow wpc.conf.executable_file_extensions to be changed from command line
		for filename in wpc.utils.dirwalk(dir, wpc.conf.executable_file_extensions, include_dirs):
			#print "[D] Processing: " + filename
			f = File(filename)
			# TODO would it be helpful to add tags to files - e.g. executable, executable_dir, program_files, etc.?
			#      we might be able to do clever queries later
			if f.is_replaceable():
				print "[D]: Replaceable: " + f.get_name()
				
			continue
			#print "[D] Analysing: " + f.get_name()
			a = f.get_dangerous_aces()
				
			if not a == []:
				if f.is_dir():
					report.get_by_id("WPC001").add_supporting_data('writable_dirs', fileAcl(f.get_name(), a))
				elif f.is_file():
					report.get_by_id("WPC001").add_supporting_data('writable_progs', fileAcl(f.get_name(), a))	
				else:
					print "[E] Ignoring thing that isn't file or directory: " + f.get_name()
	
# ------------------------ Main Code Starts Here ---------------------

# Parse command line arguments
options = parseOptions()
	
# Initialise WPC
# TODO be able to enable/disable caching
wpc.utils.init(options)

# Object to hold all the issues we find
report = issues()

# Dump data if required
if options.dump_mode:
	
	if options.do_services:
		dump_services(options)

	if options.do_drivers:
		dump_drivers(options)

	if options.do_processes:
		dump_processes(options)
		
	if options.do_users:
		dump_users(options)
		
	if options.do_groups:
		dump_groups(options)
		
	if options.do_registry:
		dump_registry(options)

# Check services
if options.audit_mode:
	if options.do_services:
		audit_services(report)

	if options.do_drivers:
		audit_drivers(report)

	if options.do_processes:
		audit_processes(report)
		
	if options.do_users:
		audit_users(report)
		
	if options.do_groups:
		audit_groups(report)

	if options.do_registry:
		audit_registry(report)

	print report.as_text()

	#wpc.conf.cache.print_stats()

