# report.issue
# report.fileAcl
# report.serviceFileAcl
# report.serviceAcl
# report.shareAcl
# report.dirAcl?
# report.registryKeyAcl

from wpc.acelist import acelist


# This is a bit like a file object, but we may be reporting only some of the ACEs from the DACL
class fileAcl:
    def __init__(self, f, a):
        self.acelist = None
        self.filename = None
        self.set_filename(f)
        self.set_acelist(a)

    def set_acelist(self, aces):
        self.acelist = acelist()
        for ace in aces:
            self.acelist.add(ace)

    def set_filename(self, f):
        self.filename = f

    def get_filename(self):
        return self.filename

    def get_acelist(self):
        return self.acelist

    def as_text(self):
        t = ''
        for ace in self.get_acelist().get_aces():
            t += self.get_filename() + ":\n  " + ace.as_text() + "\n"
        return t

    # TODO owner?