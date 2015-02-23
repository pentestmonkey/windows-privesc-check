from wpc.regkey import regkey
from wpc.softwarepackage import softwarepackage
import wpc.conf
import re 

class softwarepackages():
    def __init__(self):
        self.packages = []
    
    
    def get_installed_packages(self):
        print '[+] Checking installed software'
        uninstall = regkey('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall')
        self.packages = self._get_packages_from_key(uninstall)
    
        if wpc.conf.on64bitwindows:
            print '[+] Checking installed software (WoW64 enabled)'
            uninstall = regkey('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall', view=64)
            self.packages = self.packages + self._get_packages_from_key(uninstall)

        return self.packages

    def _get_packages_from_key(self, uninstall):
        packages = []
        if uninstall.is_present():
            for subkey in uninstall.get_subkeys():
                name = wpc.utils.to_printable(subkey.get_value("DisplayName"))
                if not name is None:
                    packages.append(softwarepackage(subkey))
        return packages
    
    
    def get_software_types(self):
        return wpc.conf.software.keys()
        
        
    def get_software_of_type(self, sw_type):
        packages = []
        for package in self.get_installed_packages():
            if package.is_of_type(sw_type):
                packages.append(package)
        return packages
    
            
    def get_vulnerable_software(self):
        packages = []
        for package in self.get_installed_packages():
            if package.is_vulnerable_version():
                packages.append(package)
        return packages