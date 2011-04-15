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
		resume = 0
		keepgoing = 1
		members = []
		principals = []

		# Non-local groups
		level = 0 # we can't get SID
		for member in wpc.conf.cache.NetGroupGetUsers(wpc.conf.remote_server, self.get_name(), level):
			p = None
			(sid, domain, type) = wpc.conf.cache.LookupAccountName(wpc.conf.remote_server, member['name'])
			if wpc.conf.sid_is_group_type[type]:
				p = group(sid)
			else:
				p = user(sid)
				
			if not p.get_sid() in map(lambda x: x.get_sid(), ignore_principals):
				principals.append(p)

		
		# Local Groups		
		level = 2
		for member in wpc.conf.cache.NetLocalGroupGetMembers(wpc.conf.remote_server, self.get_name(), level):
			p = None
			if wpc.conf.sid_is_group_type[member['sidusage']]:
				p = group(member['sid'])
			else:
				p = user(member['sid'])
				
			if not p.get_sid() in map(lambda x: x.get_sid(), ignore_principals):
				principals.append(p)


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
		
		
		