from wpc.process import process
from wpc.principal import principal
import win32process
import win32ts
import wpc.conf

class processes:
	def __init__(self):
		self.processes = []
		
	def add(self, p):
		self.processes.append(p)
	
	def get_all(self):
		if self.processes == []:
			pids = win32process.EnumProcesses()
			try:
				proc_infos = win32ts.WTSEnumerateProcesses(wpc.conf.remote_server, 1, 0)
			except:
				proc_infos = []
				pass
				
			for pid in pids:
				p = process(pid)
				self.add(p)
			
			for proc_info in proc_infos:
				pid = proc_info[1]
				p = self.find_by_pid(pid)
				if p: # might fail to find process - race condition
					p.set_wts_session_id(proc_info[0])
					p.set_wts_name(proc_info[2])
					if proc_info[3]: # sometimes None
						p.set_wts_sid(principal(proc_info[3]))
				
		return self.processes
		
	def find_by_pid(self, pid):
		for p in self.processes:
			if p.pid == pid:
				return p
		return None