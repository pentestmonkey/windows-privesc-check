import wpc.utils
import re

class softwarepackage():
    def __init__(self, packagekey):
        self.packagekey = packagekey
        self.name = wpc.utils.to_printable(packagekey.get_value("DisplayName"))
        self.publisher = wpc.utils.to_printable(packagekey.get_value("Publisher"))
        self.version = wpc.utils.to_printable(packagekey.get_value("DisplayVersion"))
        self.date = wpc.utils.to_printable(packagekey.get_value("InstallDate"))
        self.is64bit = 0
        self.is32bit = 1
        self.bad_version = None
        if packagekey.get_view() and packagekey.get_view() == 64:
            self.is64bit = 1
            self.is32bit = 0

    def get_name(self):
        return self.name
    
    def get_publisher(self):
        return self.publisher
    
    def get_version(self):
        return self.version
    
    def get_arch(self):
        if self.is32bit:
            return 32
        return 64
    
    def get_date(self):
        return self.date
    
    def get_bad_version(self):
        return self.bad_version
    
    def is_of_type(self, sw_category):          
                    if sw_category in wpc.conf.software.keys():
                        for sw_prefix in wpc.conf.software[sw_category]['names']:
                            if self.get_name().lower().find(sw_prefix.lower()) == 0:
                                return 1
                    return 0

    def is_vulnerable_version(self):
                    version = self.get_version()
                    for vuln_info in wpc.conf.vulnerable_software_version_info:
                        if 'installed_package_re' in vuln_info:
                            m = re.search(vuln_info['installed_package_re'], self.get_name())
                            if not m:
                                continue
                        
                        if 'installed_vendor_re' in vuln_info:
                            m = re.search(vuln_info['installed_vendor_re'], self.get_publisher())
                            if not m:
                                continue
                        
                        if not vuln_info['installed_version_string_ok']:
                            if 'version_from_name_re' in vuln_info:
                                version = re.sub(vuln_info['version_from_name_re']['from_re'], vuln_info['version_from_name_re']['to_re'], self.get_name())
                        
                        self.bad_version = version
                        if wpc.utils.version_less_than_or_equal_to(version, vuln_info['newest_vulnerable_version']):
                            return 1
                        
                    return 0
                            