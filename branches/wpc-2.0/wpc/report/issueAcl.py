# report.issue
# report.fileAcl
# report.serviceFileAcl
# report.serviceAcl
# report.shareAcl
# report.dirAcl?
# report.registryKeyAcl

from wpc.acelist import acelist


# This is a genric ACL that can be rendered in a report
class issueAcl:
    def __init__(self, n, a):
        self.acelist = None
        self.name = None
        self.set_name(n)
        self.set_acelist(a)

    def set_acelist(self, aces):
        self.acelist = acelist()
        for ace in aces:
            self.acelist.add(ace)

    def set_name(self, n):
        self.name = n

    def get_name(self):
        return self.name

    def get_acelist(self):
        return self.acelist

    def as_text(self):
        t = ''
        for ace in self.get_acelist().get_aces():
            t += self.get_name() + ":\n  " + ace.as_text() + "\n"
        return t

    # TODO owner?