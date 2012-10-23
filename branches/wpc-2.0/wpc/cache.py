from wpc.sd import sd
import win32net
import win32netcon
import win32security
import wpc.file
#from wpc.file import file as wpcfile


# Basically a huge hash of all lookups
#
# There should be only one instance of the cache which is started when the script is initialised
# All classes are hard-coded to use this instance of "cache"
#
# wpc.cache # single global instance of this class
#
# Some attributes of "cache" determine how it behaves
# wpc.conf.cache...
class cache:
    def __init__(self):
        self.namefromsid = {}
        self.sidfromname = {}
        self.stringfromsid = {}
        self.sidingroup = {}
        self.files = {}
        self.regkeys = {}
        self.misses = {}
        self.hits = {}
        self.policyhandlefromserverrights = {}
        self.rightsfromhandlesid = {}
        self.namefromserveruser = {}
        self.hits['files'] = 0
        self.misses['files'] = 0
        self.hits['regkeys'] = 0
        self.misses['regkeys'] = 0
        self.hits['sd'] = 0
        self.misses['sd'] = 0
        self.hits['LookupAccountSid'] = 0
        self.misses['LookupAccountSid'] = 0
        self.hits['LookupAccountName'] = 0
        self.misses['LookupAccountName'] = 0
        self.hits['is_in_group'] = 0
        self.misses['is_in_group'] = 0

    def print_stats(self):
        for k in self.hits.keys():
            print "Hits for %s: %s" % (k, self.get_hits(k))
            print "Misses for %s: %s" % (k, self.get_misses(k))

    def sd(self, type, name):
        # TODO caching code here
        return sd(type, name)

    def File(self, name):
        f = None  # might save 1 x dict lookup
        if name in self.files.keys():
            #print "[D] Cache hitx for: " + self.files[name].get_name()
            self.hit('files')
            return self.files[name]
        else:
            self.miss('files')
            f = wpc.file.file(name)
            self.files[name] = f
        return f

    def regkey(self, name):
        f = None  # might save 1 x dict lookup
        if name in self.regkeys.keys():
            #print "[D] Cache hitx for: " + self.files[name].get_name()
            self.hit('regkeys')
            return self.regkeys[name]
        else:
            self.miss('regkeys')
            f = wpc.regkey.regkey(name)
            self.regkeys[name] = f
        return f

    def LsaOpenPolicy(self, server, rights):
        keystring = "%s%%%s" %(server, rights)
        if not keystring in self.policyhandlefromserverrights.keys():
            self.policyhandlefromserverrights[keystring] = win32security.LsaOpenPolicy(wpc.conf.remote_server, win32security.POLICY_VIEW_LOCAL_INFORMATION | win32security.POLICY_LOOKUP_NAMES)
        return self.policyhandlefromserverrights[keystring]

    def LsaEnumerateAccountRights(self, handle, sid):
        keystring = "%s%%%s" %(handle, sid)
        if not keystring in self.rightsfromhandlesid.keys():
            try:
                self.rightsfromhandlesid[keystring] = win32security.LsaEnumerateAccountRights(handle, sid)
            except:
                self.rightsfromhandlesid[keystring] = ""

        return self.rightsfromhandlesid[keystring]

    def LookupAccountSid(self, server, s):
        sid = win32security.ConvertSidToStringSid(s)
        if not server in self.namefromsid.keys():
            self.namefromsid[server] = {}
        if not sid in self.namefromsid[server].keys():
            try:
                self.namefromsid[server][sid] = win32security.LookupAccountSid(server, s)
            except:
                self.namefromsid[server][sid] = (win32security.ConvertSidToStringSid(s), "[unknown]", 8)
            self.miss('LookupAccountSid')
        else:
            self.hit('LookupAccountSid')

        return self.namefromsid[server][sid]

    def LookupAccountName(self, server, name):
        if not server in self.sidfromname.keys():
            self.sidfromname[server] = {}
        if not name in self.sidfromname[server].keys():
            try:
                self.sidfromname[server][name] = win32security.LookupAccountName(server, name)
            except:
                self.sidfromname[server][name] = None
            self.miss('LookupAccountName')
        else:
            self.hit('LookupAccountName')

        return self.sidfromname[server][name]

    def hit(self, name):
        self.hits[name] = self.hits[name] + 1

    def miss(self, name):
        self.misses[name] = self.misses[name] + 1

    def get_hits(self, name):
        return self.hits[name]

    def get_misses(self, name):
        return self.misses[name]

    def is_in_group(self, p, group):
#        print "cache.is_in_group called"
        #sid = win32security.ConvertSidToStringSid(s)
#        print "[D] 1"
        sid = p.get_sid_string()
        if not sid in self.sidingroup.keys():
            self.sidingroup[sid] = {}
#        print "[D] 2"
#        print "is_in_group group.get_sid_string(): %s" % group.get_sid_string()
#        print "is_in_group sid: %s" % sid
#        print "members"
#        print map(lambda x: x.get_sid_string(), group.get_members())
        if not group.get_sid_string() in self.sidingroup[sid].keys():
            self.sidingroup[sid][group.get_sid_string()] = 0
            self.miss('is_in_group')
            #print "Miss for is_in_group"
            if p.get_sid_string() in map(lambda x: x.get_sid_string(), group.get_members()):
                self.sidingroup[sid][group.get_sid_string()] = 1
#            print "[D] 3"
        else:
            #print "Hit for is_in_group"
            self.hit('is_in_group')
#        print "Returning: %s" % self.sidingroup[sid][group.get_sid_string()]
        return self.sidingroup[sid][group.get_sid_string()]

    def NetGroupGetUsers(self, server, name, level):
        keepgoing = 1
        resume = 0
        members = []
        while keepgoing:
            try:
                m, total, resume = win32net.NetGroupGetUsers(server, name, level, resume, win32netcon.MAX_PREFERRED_LENGTH)
            except:
                return []

            for member in m:
                members.append(member)

            if not resume:
                keepgoing = 0
        return members

    def NetLocalGroupGetMembers(self, server, name, level):
        keepgoing = 1
        resume = 0
        members = []
        while keepgoing:
            try:
                m, total, resume = win32net.NetLocalGroupGetMembers(server, name, level, resume, win32netcon.MAX_PREFERRED_LENGTH)
            except:
                return []

            for member in m:
                members.append(member)

            if not resume:
                keepgoing = 0
        return members