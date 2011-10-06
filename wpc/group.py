import win32security
import ntsecuritycon
import _winreg
import win32service
import win32con
import win32net
import win32netcon
from wpc.principal import principal
from wpc.user import user
import wpc.conf
# These have members
class group(principal):
	def get_members(self):
		#print "get_members called for %s" % self.get_fq_name()
		return self.get_members_except([self])
	
	def get_members_except(self, ignore_principals):
		#for i in ignore_principals:
		#	print "Ignoring: " + i.get_fq_name()
		resume = 0
		keepgoing = 1
		members = []
		principals = []
		#print "group %s is type %s" % (self.get_fq_name(), self.get_type_string())
		#while keepgoing:
			#try:
			#	m, total, resume = win32net.NetLocalGroupGetMembers(wpc.conf.remote_server, self.get_name(), 2 , resume, win32netcon.MAX_PREFERRED_LENGTH)
			#except:
			#	return []
			#print m
			#for member in m:
				#members.append(member)
		for member in wpc.conf.cache.NetLocalGroupGetMembers(wpc.conf.remote_server, self.get_name(), 2):
			#print "%s has member %s" % (self.get_fq_name(), member['domainandname'])
			p = None
			if wpc.conf.sid_is_group_type[member['sidusage']]:
				p = group(member['sid'])
			else:
				p = user(member['sid'])
				
			#for i in ignore_principals:
			#	print "checking if %s is %s" % (p.get_sid(), i.get_sid())
			if not p.get_sid() in map(lambda x: x.get_sid(), ignore_principals):
			#	print "%s is new" % p.get_sid()
				principals.append(p)
			#else:
			#	print "%s is NOT new" % p.get_sid()
		if not resume:
			keepgoing = 0

		# TODO: should be able to list members of group "None"
				
		# TODO: make this an option
		# TODO: If we also want to list members of subgroups recursively...
		ignore_principals.extend(principals)
		for p in principals:
			if p.is_group_type():
				g = group(member['sid'])
#				print "[D] %s has member %s (Group)" % (self.get_fq_name(), g.get_fq_name())
#				principals.append(g)
				for new_principals in g.get_members_except(ignore_principals):
					principals.append(new_principals)
				
		return principals
		
		
		