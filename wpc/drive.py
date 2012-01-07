import win32api
import win32con
import win32file


# NB: Only works for fixed drives - or you get "device not ready" error
class drive():
    def __init__(self, drivename):
        self.filesystem = None
        self.drivetype = None
        self.drivename = drivename
        self.driveinfo = win32api.GetVolumeInformation(drivename)

    def get_name(self):
        return self.drivename

    def get_fs(self):
        if not self.filesystem:
            self.filesystem = self.driveinfo[4]

        return self.filesystem

    def get_type(self):
        if not self.drivetype:
            self.drivetype = win32file.GetDriveType(self.driveinfo)

        return self.drivetype

    def is_fixed_drive(self):
        if self.get_type() == win32con.DRIVE_FIXED:
            return 1
        return 0
