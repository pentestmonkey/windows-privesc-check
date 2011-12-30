import win32security
import ntsecuritycon
import _winreg
import win32service
import win32con
import win32net
import wpc.conf
from wpc.principal import principal
#from wpc.group import group as group
import win32net

# These have properties such as active, workstations that groups don't have
class user(principal):
	def get_groups(self):
		principals = []
		g1 = []
		g2 = []
		print "user.get_groups called for " + self.get_name()
		try:
			g1 = win32net.NetUserGetLocalGroups(wpc.conf.remote_server, self.get_name(), 0)
		except:
			pass
		try:
			g2 = win32net.NetUserGetGroups(wpc.conf.remote_server, self.get_name())
		except:
			pass
		for g in g2:
			g1.append(g[0])
		for group in g1:
			gsid, s, i = win32security.LookupAccountName(wpc.conf.remote_server, group)
			principals.append(Group(gsid))	
		return principals
		
	def get_info(self, key):
		if not self.info:
			try:
				self.info = win32net.NetUserGetInfo(None, self.get_fq_name, 4)
				return self.info[key]
			except:
				pass
		return None
			