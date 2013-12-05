from wpc.principal import principal
import ntsecuritycon
import wpc.conf


class ace:
    def __init__(self, otype, ace):
        self.set_ace(ace)
        self.type = None
        self.resolved_perms = []
        self.set_otype(otype)
        self.set_type_i(ace[0][0])
        self.set_flags(ace[0][1])
        self.set_sid(ace[2])
        self.set_dperms([])
        self.set_principal(principal(ace[2]))
        self.set_perms(self.resolve_perms())

    def get_type(self):
        if not self.type:
            for i in ("ACCESS_ALLOWED_ACE_TYPE", "ACCESS_DENIED_ACE_TYPE", "SYSTEM_AUDIT_ACE_TYPE", "SYSTEM_ALARM_ACE_TYPE"):
                if getattr(ntsecuritycon, i) == self.type_i:
                    # Abbreviate
                    if i == "ACCESS_ALLOWED_ACE_TYPE":    
                        self.type = "ALLOW"
                        break
                    if i == "ACCESS_DENIED_ACE_TYPE":
                        self.type = "DENY"
                        break
            if not self.type:
                self.type = "UNKNOWN_ACE_TYPE_" + self.type_i
        return self.type

    def get_sid(self):
        return self.sid

    def get_flags(self):
        return self.flags

    def set_principal(self, principal):
        self.principal = principal

    def set_dperms(self, dperms):
        self.dperms = dperms

    def set_sid(self, sid):
        self.sid = sid

    def set_flags(self, flags):
        self.flags = flags

    def set_ace(self, ace):
        self.ace = ace

    def set_type_i(self, type_i):
        self.type_i = type_i

    def set_otype(self, otype):
        self.otype = otype

    def set_type(self, type):
        self.type = type

    def get_principal(self):
        return self.principal

    def get_otype(self):
        return self.otype

    def resolve_perms(self):
        if self.resolved_perms == []: 
            for mod, perms_tuple in wpc.conf.all_perms[self.get_otype()].iteritems():
                for perm in perms_tuple:
                    g = getattr(mod, perm)  # save a getattr call
                    if g & self.ace[1] == g:
                        self.resolved_perms.append(perm)
        return self.resolved_perms

    def get_perms(self):
        return self.perms

    def get_ace(self):
        return self.ace

    def copy(self):
        new = ace(self.get_otype(), self.get_ace())
        return new

    def set_perms(self, perms):
        self.perms = perms

    def has_perm(self, perm):
        if self.get_type() == "ALLOW":  # we ignore DENY aces - mostly correct TODO they're actually checked before ALLOWs.  False negatives if user is blocked by DENY
            for p in self.get_perms():
                if p == perm:
                    return 1
        return 0

    def get_perms_dangerous(self):
        if self.dperms == []:
            if self.get_type() == "ALLOW":  # we ignore DENY aces - mostly correct TODO they're actually checked before ALLOWs.  False negatives if user is blocked by DENY
                for p in self.get_perms():
                    for k in wpc.conf.dangerous_perms_write[self.get_otype()]:
                        if p in wpc.conf.dangerous_perms_write[self.get_otype()][k]:
                            self.dperms.append(p)
        return self.dperms

    def as_text(self):
        return self.get_type() + " " + self.get_principal().get_fq_name() + ": \n    " + "\n    ".join(self.get_perms())

    def as_tab_delim(self, name):
        lines = []
        for perm in self.get_perms():
            lines.append("%s\t%s\t%s\t%s\t%s" % ("RegKey", name, self.get_type(), self.get_principal().get_fq_name(), perm))
        return lines

    def as_tab_delim2(self, name, value):
        if value == "":
            value = "(Default)"
        lines = []
        for perm in self.get_perms():
            lines.append("%s\t%s\t%s\t%s\t%s\t%s" % ("RegKeyVal", name, value, self.get_type(), self.get_principal().get_fq_name(), perm))
        return lines

    def as_tab_delim3(self, name, value, data):
        if value == "":
            value = "(Default)"
        lines = []
        for perm in self.get_perms():
            lines.append("%s\t%s\t%s\t%s\t%s\t%s\t%s" % ("RegKeyValData", name, value, repr(data), self.get_type(), self.get_principal().get_fq_name(), perm))
        return lines
#    def dangerous_as_text(self):
#        return self.get_type() + " " + self.get_principal().get_fq_name() + ": \n  " + "\n  ".join(self.get_perms_dangerous())
