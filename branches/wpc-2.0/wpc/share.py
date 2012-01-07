from wpc.file import file as File
from wpc.sd import sd
import win32net
import wpc.conf


class share:
    def __init__(self, name):
        self.name = name
        self.info = None
        self.description = None
        self.passwd = None
        self.current_uses = None
        self.max_uses = None
        self.path = None
        self.type = None
        self.sd = None
        self.permissions = None

    def get_name(self):
        return self.name

    def get_info(self):
        if not self.info:
            try:
                shareinfo = win32net.NetShareGetInfo(wpc.conf.remote_server, self.get_name(), 502)
                self.description = shareinfo['reserved']
                self.passwd = shareinfo['passwd']
                self.current_uses = shareinfo['current_uses']
                self.max_uses = shareinfo['max_uses']

                if shareinfo['path']:
                #    self.path = File(shareinfo['path'])
                #else:
                    self.path = shareinfo['path']

                self.type = shareinfo['type']

                if shareinfo['security_descriptor']:
                    self.sd = sd('share', shareinfo['security_descriptor'])
                else:
                    self.sd = None

                self.perms = shareinfo['permissions']

                self.info = shareinfo
            except:
                pass
        return self.info

    def get_description(self):
        if not self.description:
            self.get_info()

        return self.description

    def get_path(self):
        if not self.path:
            self.get_info()

        return self.path

    def get_passwd(self):
        if not self.passwd:
            self.get_info()

        return self.passwd

    def get_current_uses(self):
        if not self.current_uses:
            self.get_info()

        return self.current_uses

    def get_max_uses(self):
        if not self.max_uses:
            self.get_info()

        return self.max_uses

    # Ignore this.
    # "Note that Windows does not support share-level security."
    # http://msdn.microsoft.com/en-us/library/bb525410(v=vs.85).aspx
    def get_permissions(self):
        if not self.permissions:
            self.get_info()

        return self.permissions

    def get_sd(self):
        if not self.sd:
            self.get_info()

        return self.sd

    def as_text(self):
        t = '--- start share ---\n'
        t += 'Share Name: ' + str(self.get_name()) + '\n'
        t += 'Description: ' + str(self.get_description()) + '\n'
        if self.get_path():
            t += 'Path: ' + str(self.get_path()) + '\n'
        else:
            t += 'Path: None\n'
        t += 'Passwd: ' + str(self.get_passwd()) + '\n'
        t += 'Current Uses: ' + str(self.get_current_uses()) + '\n'
        t += 'Max Uses: ' + str(self.get_max_uses()) + '\n'
        t += 'Permissions: ' + str(self.get_permissions()) + '\n'

        if self.get_path():
            f = File(self.get_path())
            if f.exists():
                if f.get_sd():
                    t += 'Directory Security Descriptor:\n'
                    t += f.get_sd().as_text() + '\n'
                else:
                    t += 'Directory Security Descriptor: None (can\'t read sd)\n'
            else:
                t += 'Directory Security Descriptor: None (path doesn\'t exist)\n'
        else:
            t += 'Directory Security Descriptor: None (no path)\n'

        if self.get_sd():
            t += 'Share Security Descriptor:\n'
            t += self.get_sd().as_text() + '\n'
        else:
            t += 'Share Security Descriptor: None\n'

        t += '--- end share ---\n'
        return t