from wpc.ace import ace
from wpc.acelist import acelist
from wpc.principal import principal
import win32security
import wpc.conf


class sd(acelist):
    def __init__(self, type, secdesc):
        self.type = type
        self.sd = secdesc
        self.owner = None
        self.group = None
        self.owner_sid = None
        self.group_sid = None
        self.dacl = None
        self.acelist = None
        self.untrusted_owner = None

    def get_aces(self):
        if self.acelist == None:
            self.acelist = acelist()
            dacl = self.get_dacl()
            if dacl:  # Some files will have no DACL - e.g. on HGFS file systems
                for ace_no in range(0, self.dacl.GetAceCount()):
                    #print "[D] ACE #%d" % ace_no
                    self.acelist.add(ace(self.get_type(), dacl.GetAce(ace_no)))
        return self.acelist.get_aces()

    def get_acelist(self):
        if self.acelist == None:
            self.get_aces()  # side effect is defining self.acelist
        return self.acelist

    def get_type(self):
        return self.type

    def dangerous_as_text(self):
        s = ""

        o = self.get_owner()
        if o:
            s += "Owner:    " + self.get_owner().get_fq_name() + "\n"
        else:
            s += "Owner:   [none] \n"

        g = self.get_group()
        if g:
            s += "Group:    " + self.get_group().get_fq_name() + "\n"
        else:
            s += "Group:   [none] \n"

        for a in self.get_aces_dangerous():
            s += a.as_text() + "\n"
        return s

    def dump(self):
        print self.as_text()

    def perms_for(self, principal):
        # TODO use all_perms above
        pass

    def dangerous_perms_for(self):
        pass

    def dangerous_perms_for_principal(self, principal):
        # TODO use dangerous_perms_write above
        pass

    def writable_by(self, principals):
        # TODO check parent dir?
        # TODO use dangerous_perms_write above
        pass

    def get_sd(self):
        return self.sd

    def get_dacl(self):
        if self.dacl == None:
            self.dacl = self.get_sd().GetSecurityDescriptorDacl()
        return self.dacl

    def get_owner(self):
        if not self.owner:
            owner_sid = self.get_owner_sid()
            if owner_sid:
                self.owner = principal(self.get_owner_sid())
            else:
                self.owner = None
        return self.owner

    def get_group(self):
        if not self.group:
            group_sid = self.get_group_sid()
            if group_sid:
                self.group = principal(self.get_group_sid())
            else:
                self.group = None
        return self.group

    def get_group_sid(self):
        if self.group_sid == None:
            self.group_sid = self.get_sd().GetSecurityDescriptorGroup()
        return self.group_sid

    def get_owner_sid(self):
        if self.owner_sid == None:
            self.owner_sid = self.get_sd().GetSecurityDescriptorOwner()
        return self.owner_sid

    def get_remote_server(self):
        return wpc.conf.remote_server

    def get_owner_string(self):
        owner_name, owner_domain, type = self.get_owner_tuple()
        return owner_domain + "\\" + owner_name

    def get_owner_name(self):
        if self.owner_name == None:
            self.owner_name = win32security.ConvertSidToStringSid(self.get_owner_sid)
        return self.owner_name

    def set_owner_name(self, name):
        self.owner_name = name

    def set_owner_domain(self, name):
        self.owner_domain = name

    def get_owner_tuple(self):
        owner_name, owner_domain, type = wpc.conf.cache.LookupAccountSid(self.get_remote_server(), self.get_owner_sid())
        self.set_owner_name(owner_name)
        self.set_owner_domain(owner_domain)
        return owner_name, owner_domain, type

    def owner_is_untrusted(self):
        if not self.untrusted_owner:
            self.untrusted_owner = self.get_owner().is_trusted() ^ 1  # xor
        return self.untrusted_owner

    def as_text(self):
        return self._as_text(0)

    def untrusted_as_text(self):
        return self._as_text(1)

    def _as_text(self, flag):
        s = "--- start %s security descriptor ---\n" % self.get_type()
        o = self.get_owner()
        if o:
            s += "Owner:    " + self.get_owner().get_fq_name() + "\n"
        else:
            s += "Owner:   [none] \n"

        g = self.get_group()
        if g:
            s += "Group:    " + self.get_group().get_fq_name() + "\n"
        else:
            s += "Group:   [none] \n"
        for a in self.get_aces():
            if flag:
                if not a.get_principal().is_trusted():
                    s += a.as_text() + "\n"
            else:
                s += a.as_text() + "\n"            
        s += "--- end security descriptor ---\n"
        return s
