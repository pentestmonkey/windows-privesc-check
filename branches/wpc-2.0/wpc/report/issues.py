from wpc.report.issue import issue


# TODO should this class contain info about the scan?  or define a new class called report?
# Version of script
# Date, time of audit
# Who the audit ran as (username, groups, privs)
# ...
class issues:
    def __init__(self):
        self.issues = []

    def get_by_id(self, identifier):
        # search for issue
        for i in self.issues:
            if i.get_id() == identifier:
                return i

        # create new issue
        i = issue(identifier)
        self.add_issue(i)
        return i

    def add_issue(self, i):
        self.issues.append(i)

    def add_supporting_data(self, identifier, k, v):
        self.get_by_id(identifier).add_supporting_data(k, v)

    def get_all(self):
        return self.issues

    def as_text(self):
        t = '------------------------------------------------------------------' + "\n"
        for i in self.get_all():
            t += i.as_text()
        return t
