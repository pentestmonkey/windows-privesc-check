from wpc.principal import principal
import win32net
import win32security
import wpc.conf
#from wpc.group import group as group


# These have properties such as active, workstations that groups don't have
class user(principal):
    def get_groups(self):
        if self.member_of:
            return self.member_of

        from wpc.group import group as Group # we have to import here to avoid circular import
        
        g1 = []
        g2 = []
        
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
            gsid, s, i = wpc.conf.cache.LookupAccountName(wpc.conf.remote_server, group)
            self.member_of.append(Group(gsid))
            
        return self.member_of

    def get_info(self, key):
        if not self.info:
            try:
                self.info = win32net.NetUserGetInfo(None, self.get_fq_name, 4)
                return self.info[key]
            except:
                pass
        return None
