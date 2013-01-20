import wpc.conf
from wpc.principal import principal
import win32net


# These have properties such as active, workstations that groups don't have
class user(principal):
    def __init__(self, *args, **kwargs):
        principal.__init__(self, *args, **kwargs)
        self.member_of = []
        self.effective_privileges = []

        # populate principal.info['member_of'] (groups this user belongs to)
#        self.add_info({'member_of': " ".join(self.get_groups_fq_name())})

        # populate principal.info['privileges'] (privs of user + privs of user's groups)
#        self.add_info({'privileges': " ".join(self.get_effective_privileges())})

    def get_effective_privileges(self):
        if self.effective_privileges:
            return self.effective_privileges

        gprivileges = []
        for g in self.get_groups():
            gprivileges = list(list(gprivileges) + list(g.get_privileges()))

        return sorted(list(set(list(self.get_privileges()) + list(gprivileges))))

    def get_groups_fq_name(self):
        if not self.member_of:
            self.member_of = self.get_groups()

        return map(lambda x: x.get_fq_name(), self.member_of)
    
    def get_flags(self):
        flags = 0
        info = win32net.NetUserGetInfo(wpc.conf.remote_server, self.get_name(), 1)
        if info['flags']:
            flags = info['flags']
        return flags
    
    def get_password_age(self):
        password_age = 0
        info = win32net.NetUserGetInfo(wpc.conf.remote_server, self.get_name(), 1)
        if info['password_age']:
            password_age = info['password_age']
        return password_age
       
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
