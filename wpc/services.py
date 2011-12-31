from wpc.service import service
import win32service
import wpc.conf


class services:
    def __init__(self):
        self.scm = None
        self.type = win32service.SERVICE_WIN32
        self.services = []
        self.get_services()

    def add(self, s):
        self.services.append(s)

    def get_type(self):
        return self.type

    def add_all(self):
        for s in win32service.EnumServicesStatus(self.get_scm(), self.get_type(), win32service.SERVICE_STATE_ALL):
            short_name = s[0]
            self.add(service(self.get_scm(), short_name))

    def get_services(self):
        # populate self.services with a complete list of services if we haven't already
        if self.services == []:
            self.add_all()

        return self.services

    def get_scm(self):
        if not self.scm:
            self.scm = win32service.OpenSCManager(self.get_remote_server(), None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
        return self.scm

    def get_remote_server(self):
        return wpc.conf.remote_server

    def get_services_by_user_perm(self, user, perm):
        # list of services that "user" can do "perm" to (e.g. start, reconfigure)
        pass

    def get_services_by_run_as(self, run_as):
        # list of wpc.service objects that run as "run_as"
        pass


class drivers(services):
    def __init__(self):
        self.type = win32service.SERVICE_DRIVER
        self.scm = None
        self.services = []
        self.get_services()
