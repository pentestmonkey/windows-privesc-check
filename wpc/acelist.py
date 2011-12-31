from wpc.ace import ace
import ntsecuritycon
import win32security


# just a list of ACEs.  No owner, group, dacl, sd
# we abstrace this out so we can chain searchs:
# sd.get_aces_untrusted().get_aces_dangerous()
class acelist:
    def __init__(self):
        self.aces = []
        self.untrusted_acelist = None
        pass

    def add(self, ace):
        # http://msdn.microsoft.com/en-us/library/aa374919(v=vs.85).aspx
        # Ignore ACE if it doesn't apply to this object (i.e. it is instead just inherited by children)
        if not ace.get_flags() & ntsecuritycon.INHERIT_ONLY_ACE:
            self.aces.append(ace)

    def get_aces(self):
        return self.aces

    def get_aces_for(self, principal):
        a = acelist()
        for ace in self.get_aces():
            if principal.get_sid() == ace.get_sid():
                a.add(ace)
        return a

    def get_untrusted(self):
        if not self.untrusted_acelist:
            self.untrusted_acelist = acelist()
            for ace in self.get_aces():
                if not ace.get_principal().is_trusted():
                    self.untrusted_acelist.add(ace)
        return self.untrusted_acelist

    def get_dangerous_perms(self):
        a = acelist()
        for ace in self.get_aces():
            if not ace.get_perms_dangerous() == []:
                newace = ace.copy()
                newace.set_perms(newace.get_perms_dangerous())
                a.add(newace)
        return a

    def get_aces_with_perms(self, perms):
        a = acelist()
        for ace in self.get_aces():
            found_perms = []
            for p in perms:
                if ace.has_perm(p):
                    found_perms.append(p)
            if not found_perms == []:
                newace = ace.copy()
                newace.set_perms(found_perms)
                a.add(newace)
        return a

    def get_aces_except_for(self, principals):
        a = acelist
        for ace in self.get_aces():
            trusted = 0
            for p in principals:
                #print "comparing %s with %s" % (p.get_sid(), ace.get_sid())
                if p.get_sid() == ace.get_sid():
                    trusted = 1
                    break
            if not trusted:
                a.add(ace)
        return a

    def as_text(self):
        for ace in self.get_aces():
            print ace.as_text()