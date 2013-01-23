from wpc.user import user
import win32net
import wpc.conf
import pywintypes


class users():
    def __init__(self):
        self.users = []

    def get_filtered(self, ):
        if self.users == []:
            try:
                level = 1
                resume = 0
                while True:
                    userlist, total, resume = win32net.NetUserEnum(wpc.conf.remote_server, level, 0, resume, 999999)
                    #print u
                    for u in userlist:
                        # self.users.append(user['name'])
                        #try:
                            sid, name, type = wpc.conf.cache.LookupAccountName(wpc.conf.remote_server, u['name'])
                            self.users.append(user(sid))
                        #except:
                        #    print "[E] failed to lookup sid of %s" % user['name']
                    if resume == 0:
                        break
            except pywintypes.error as e:
                print "[E] %s: %s" % (e[1], e[2])
        return self.users

    def get_all(self):
        if self.users == []:
            try:
                level = 0
                resume = 0
                while True:
                    userlist, total, resume = win32net.NetUserEnum(wpc.conf.remote_server, level, 0, resume, 999999)
                    #print u
                    for u in userlist:
                        # self.users.append(user['name'])
                        #try:
                            sid, name, type = wpc.conf.cache.LookupAccountName(wpc.conf.remote_server, u['name'])
                            self.users.append(user(sid))
                        #except:
                        #    print "[E] failed to lookup sid of %s" % user['name']
                    if resume == 0:
                        break
            except pywintypes.error as e:
                print "[E] %s: %s" % (e[1], e[2])
        return self.users
