import subprocess
import os
import re
from wpc.mspatchdb import mspatchdb


# These have members
class patchdata():
    def __init__(self, opts):
        self.installed_patches = []
        self.os = {}
        self.verbose = 0
        if 'verbose' in opts:
            self.verbose = opts['verbose']
        self.os['spreadsheet_string'] = None
        if 'os_string' in opts:
            self.os['spreadsheet_string'] = opts['os_string']
        self.os["info"] = {}
        self.db = None
        if 'patchdb' in opts.keys():
            self.db = opts['patchdb']
        elif 'patchfile' in opts.keys():
            self.db = mspatchdb({'file': opts['patchfile']})
        else:
            self.db = mspatchdb()

    def record_installed_patch(self, patch):
        # TODO dedup
        self.installed_patches.append(patch)

    def get_installed_patches(self):
        if not self.installed_patches:
            self.parse_installed_patches_from_systeminfo()
        return self.installed_patches

    def get_os_info(self):
        return self.os['info']

    def parse_installed_patches_from_systeminfo(self):
        output = subprocess.check_output("systeminfo", stderr = open(os.devnull, 'w'))
        for line in output.splitlines():
            m = re.search("OS Name:\s+.*Windows(?:\(R\))? (7|XP|Server 2003|Vista|Server 2008 R2|Server 2012)", line)
            if m and m.group(1):
                self.os['info']['winver'] = m.group(1)

            m = re.search("OS Version:.*Service Pack (\d+)", line)
            if m and m.group(1):
                self.os['info']['sp'] = m.group(1)

            m = re.search("System [Tt]ype:.*(86|64)", line)
            if m and m.group(1):
                self.os['info']['arch'] = m.group(1)

            m = re.search("^\s+\[\d+\]:\s+(?:KB|Q)?(\d{6,7})", line)
            if m and m.group(1):
                # print "[+] Found installed patch: %s" % m.group(1)
                self.record_installed_patch(m.group(1))

    def get_os_string_for_ms_spreadsheet(self):
        if not ('spreadsheet_string' in self.os and self.os['spreadsheet_string']):
            self.os['spreadsheet_string'] = self.guess_os_string_for_ms_spreadsheet()
        return self.os['spreadsheet_string']

    def guess_os_string_for_ms_spreadsheet(self):
        if self.os['info']['winver']:
            if self.os['info']['winver'].find("XP") > 0 or self.os['info']['winver'].find("2003") > 0 or self.os['info']['winver'].find("NT") > 0 or self.os['info']['winver'].find("2000") > 0:
                os = "Microsoft Windows %s" % self.os['info']['winver']
            else:
                os = "Windows %s" % self.os['info']['winver']

        if 'arch' in self.os['info'].keys() and self.os['info']['arch']:
            if self.os['info']['winver'].find("Vista") > -1:
                if self.os['info']['arch'] == "64":
                    os = "%s x64 Edition" % os
            else:
                if self.os['info']['arch'] == "64":
                    os = "%s for x64-based Systems" % os
                if self.os['info']['arch'] == "32":
                    os = "%s for 32-bit Systems" % os

        if 'sp' in self.os['info'].keys() and self.os['info']['sp']:
                os = "%s Service Pack %s" % (os, self.os['info']['sp'])

        return os

    def is_msno_applied(self, msno):
        kbs = self.db.get_kbs_from_msno(msno, self.get_os_string_for_ms_spreadsheet())
        for kb in kbs:
            if kb in self.get_installed_patches():
                return 1
        return 0

    def msno_or_superseded_applied(self, msno, os, depth):
        m = re.search("(MS\d\d-\d\d\d)", msno)
        if m and m.group(1):
            msno = m.group(1)
        else:
            print "[E] Illegal msno passed: %s" % msno
        if self.is_msno_applied(msno):
            if depth == 0:
                if self.verbose:
                    print "[+] %s has been patched" % msno
            return 1
        else:
            s = self.db.superseding_patch(msno, os)
            if s:
                at_least_one_superseding_patch_applied = 0
                for patch_string in s.split(","):
                    m = re.search("(MS\d\d-\d\d\d)", patch_string)
                    if m and m.group(1):
                        if m.group(1) == msno:
                            if self.verbose:
                                print "[+] %s supersedes %s (ignoring)" % (m.group(1), msno)
                            continue

                        if self.msno_or_superseded_applied(patch_string, os, depth + 1):
                            at_least_one_superseding_patch_applied = 1
                            if self.verbose:
                                print "[+] %s supersedes %s (and has been applied)" % (m.group(1), msno)
                            return 1
                        else:
                            if self.verbose:
                                print "[+] %s supersedes %s (and has NOT been patched)" % (m.group(1), msno)

                if not at_least_one_superseding_patch_applied:
                    if depth == 0 and self.verbose:
                        print "[+] VULNERABLE.  %s has not been patched.  There are superseding patches but none have been applied." % (msno)
                    return 0
            else:
                if depth == 0 and self.verbose:
                    print "[+] VULNERABLE.  %s has not been patched and it has no superseding patches." % (msno)
                return 0
