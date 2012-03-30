from wpc.group import group
import win32net
import wpc.conf


class groups():
    def __init__(self):
        self.groups = []

    def get_all(self):
        if self.groups == []:
            try:
                level = 0
                resume = 0
                while True:
                    grouplist, total, resume = win32net.NetGroupEnum(wpc.conf.remote_server, level, resume, 999999)
                    for u in grouplist:
                        try:
                            sid, name, type = wpc.conf.cache.LookupAccountName(wpc.conf.remote_server, u['name'])
                            self.groups.append(group(sid))
                        except:
                            print "[E] failed to lookup sid of %s" % group['name']
                    if resume == 0:
                        break
            except:
                print "[E] NetGroupEnum failed"
            try:
                level = 0
                resume = 0
                while True:
                    grouplist, total, resume = win32net.NetLocalGroupEnum(wpc.conf.remote_server, level, resume, 999999)
                    for u in grouplist:
                        try:
                            sid, name, type = wpc.conf.cache.LookupAccountName(wpc.conf.remote_server, u['name'])
                            self.groups.append(group(sid))
                        except:
                            print "[E] failed to lookup sid of %s" % group['name']
                    if resume == 0:
                        break
            except:
                print "[E] NetLocalGroupEnum failed"
        return self.groups
