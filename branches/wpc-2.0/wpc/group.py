from wpc.principal import principal
from wpc.user import user
import ntsecuritycon
import win32security
import wpc.conf


# These have members
class group(principal):
    def get_members(self):
#        print "get_members called for %s" % self.get_fq_name()
        return self.get_members_except([self])

    def get_members_except(self, ignore_principals):
        #for i in ignore_principals:
        #    print "Ignoring: " + i.get_fq_name()
        resume = 0
        keepgoing = 1
        members = []
        principals = []
        #print "group %s is type %s" % (self.get_fq_name(), self.get_type_string())
        #while keepgoing:
            #try:
            #    m, total, resume = win32net.NetLocalGroupGetMembers(wpc.conf.remote_server, self.get_name(), 2 , resume, win32netcon.MAX_PREFERRED_LENGTH)
            #except:
            #    return []
            #print m
            #for member in m:
                #members.append(member)
#        print "[D] a"
        for member in wpc.conf.cache.NetLocalGroupGetMembers(wpc.conf.remote_server, self.get_name(), 2):
#            print "[D] b"
            #print "%s has member %s" % (self.get_fq_name(), member['domainandname'])
            p = None
#            print "[D] member[sid]: %s" % member['sid']
            if wpc.conf.sid_is_group_type[member['sidusage']]:
#                print "[D] b2"
                p = group(member['sid'])
#                print "[D] b21"
            else:
#                print "[D] b3"
                p = user(member['sid'])
#                print "[D] b31"

            #for i in ignore_principals:
            #    print "checking if %s is %s" % (p.get_sid(), i.get_sid())
            if not p.get_sid() in map(lambda x: x.get_sid(), ignore_principals):
            #    print "%s is new" % p.get_sid()
                principals.append(p)
            #else:
            #    print "%s is NOT new" % p.get_sid()
        if not resume:
            keepgoing = 0

        # TODO: should be able to list members of group "None"
#        print "[D] c"

        # TODO: make this an option
        # TODO: If we also want to list members of subgroups recursively...
        ignore_principals.extend(principals)
        for p in principals:
 #           print "[D] d"
            if p.is_group_type():
                g = group(member['sid'])
#                print "[D] %s has member %s (Group)" % (self.get_fq_name(), g.get_fq_name())
#                principals.append(g)
                for new_principals in g.get_members_except(ignore_principals):
                    principals.append(new_principals)
#        print "[D] e"

        return principals
