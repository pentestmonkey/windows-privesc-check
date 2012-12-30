from wpc.report.fileAcl import fileAcl
from wpc.sd import sd
import os
import win32security
import wpc.conf


# files or directories
class file:
    def __init__(self, name):
        # print "[D] Created file obj for " + name
        self.name = str(name).replace("\x00", "")
        self.type = None
        self.parent_dir = None
        self.replaceable_set = None
        self.replaceable = None
        self.exist = None
        self.existsset = 0
        # TODO could we defer this check?
        if os.path.isdir(self.name):
            self.type = 'dir'
            if wpc.utils.is_reparse_point(self.name):
                self.type = 'reparse_point'
                # print "[D] reparse point: %s" % self.name
        else:
            self.type = 'file'
        self.sd = None

#    def clearmem(self):
#        self.name = None
#        self.type = None
#        self.parent_dir = None
#        self.replaceable_set = None
#        self.replaceable = None
#        self.exist = None
#        self.sd = None

    def as_text(self):
        s = "Filename: " + self.get_name() + "\n"
        s += self.get_sd().as_text()
        return s

    def dump(self):
        print self.as_text()

    def get_name(self):
        return self.name

    def exists(self):
        if not self.existsset:
            try:
                self.exist = os.path.exists(self.get_name())
            except:
                self.exist = 0
            self.existsset = 1
        return self.exist

    def is_dir(self):
        if self.type == 'dir':
            return 1
        else:
            return 0

    def get_type(self):
        return self.type

    def is_file(self):
        if self.type == 'file':
            return 1
        else:
            return 0

    def get_file_acl_for_perms(self, perms):
        if self.get_sd():
            al = self.get_sd().get_acelist().get_untrusted().get_aces_with_perms(perms).get_aces()
            if al == []:
                return None
            else:
                return fileAcl(self.get_name(), al)

    def get_dangerous_aces(self):
        try:
            #print "[D] File: " + self.get_name()
            #print "[D] ACE: "
            #for a in self.get_sd().get_acelist().get_dangerous_perms().get_aces():
            #    print a.as_text()
            return self.get_sd().get_acelist().get_untrusted().get_dangerous_perms().get_aces()
        except:
            return []

    # Can an untrusted user replace this file/dir? TODO unused
    def is_replaceable(self):
        if not self.exists():
            print "[W] is_replaceable called for non-existent file %s" % self.get_name()
            return 0

        # There are a few things that could cause a file/dir to be replacable.  Firstly let's define "replaceable":
        # Replaceable file: Contents can be replaced by untrusted user.  Boils down to either write access, or being able to delete then re-add
        # Replaceable dir:  Untrusted user can deleting anything within and re-add
        #
        # The code below is a bit subtle because it's recursive.  We're checking these conditions:
        #
        # 1. File/dir is owned by an untrusted user
        # 2. File/dir allows FILE_WRITE_DAC for an untrusted user
        # 3. File/dir allows FILE_WRITE_OWNER for an untrusted user
        # 4. File allows FILE_WRITE_DATA for an untrusted user
        # 5. File allows DELETE and parent dir allows FILE_ADD_FILE for an untrusted user
        # 6. Parent dir allows FILE_DELETE_CHILD and FILE_ADD_FILE for an untrusted user
        # 7. Parent of directory or grandparent of file allows FILE_DELETE_CHILD and FILE_ADD_SUBFOLDER by untrusted user
        # 8. Parent dir allows DELETE by untrusted user and its parent allows FILE_ADD_SUBFOLDER
        # 9. Parent dir (or any parent thereof) allows WRITE_DAC for an untrusted user
        # 10. Parent dir (or any parent thereof) allows WRITE_OWNER for an untrusted user
        # 11. Parent dir (or any parent thereof) is owned by an untrusted user

        # Return cached result if we have it
        if self.replaceable_set:
            # print "[D] Cache hit for " + self.get_name()
            return self.replaceable

        # Checks applicable to both files and directories
        if self.get_sd():
            # 1. File is owned by an untrusted user
            # 11. Parent dir (or any parent thereof) is owned by an untrusted user
            # Also see below for a recursive check of parent directories
            if self.get_sd().owner_is_untrusted():
                self.replaceable_set = 1
                self.replaceable = 1
                return 1

            # 2. File allows FILE_WRITE_DAC for an untrusted user
            # 3. File allows FILE_WRITE_OWNER for an untrusted user
            # 9. Parent dir (or any parent thereof) allows WRITE_DAC for an untrusted user
            # 10. Parent dir (or any parent thereof) allows WRITE_OWNER for an untrusted user
            # Also see below for a recursive check of parent directories
            if not self.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["FILE_WRITE_DAC", "FILE_WRITE_OWNER"]).get_aces() == []:
                self.replaceable_set = 1
                self.replaceable = 1
                return 1

        # Checks applicable to only files
        if self.type == 'file':
            if self.get_sd():
                # 4. File allows FILE_WRITE_DATA for an untrusted user
                if not self.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["FILE_WRITE_DATA"]).get_aces() == []:
                    self.replaceable_set = 1
                    self.replaceable = 1
                    return 1

                # 5. File allows DELETE and parent dir allows FILE_ADD_FILE for an untrusted user
                if not self.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["DELETE"]).get_aces() == []:
                    if self.get_parent_dir().get_sd():
                        if not self.get_parent_dir().get_sd().get_acelist().get_untrusted().get_aces_with_perms(["FILE_ADD_FILE"]).get_aces() == []:
                            self.replaceable_set = 1
                            self.replaceable = 1
                            return 1

                # 6. Parent dir allows FILE_DELETE_CHILD and FILE_ADD_FILE for an untrusted user
                # NB: We don't require that a single ACE contains both perms.  If untrusted user x has FILE_DELETE_CHILD and untrusted user y has perm FILE_ADD_FILE, 
                # this is still insecure.
                if self.get_parent_dir().get_sd():
                    if not self.get_parent_dir().get_sd().get_acelist().get_untrusted().get_aces_with_perms(["FILE_ADD_FILE"]).get_aces() == [] and not self.get_parent_dir().get_sd().get_acelist().get_untrusted().get_aces_with_perms(["FILE_DELETE_CHILD"]).get_aces() == []:
                        self.replaceable_set = 1
                        self.replaceable = 1
                        return 1    

        if self.type == 'dir':
            # 7. Parent of directory or grandparent of file allows FILE_DELETE_CHILD and FILE_ADD_SUBFOLDER by untrusted user
            # 8. Parent dir allows DELETE by untrusted user and its parent allows FILE_ADD_SUBFOLDER
            if self.get_sd():
                if not self.get_sd().get_acelist().get_untrusted().get_aces_with_perms(["DELETE"]).get_aces() == []:
                    if self.get_parent_dir() and self.get_parent_dir().get_sd():
                        if not self.get_parent_dir().get_sd().get_acelist().get_untrusted().get_aces_with_perms(["FILE_ADD_SUBFOLDER"]).get_aces() == []:
                            self.replaceable_set = 1
                            self.replaceable = 1
                            return 1

            if self.get_parent_dir() and self.get_parent_dir().get_sd():
                if not self.get_parent_dir().get_sd().get_acelist().get_untrusted().get_aces_with_perms(["FILE_DELETE_CHILD", "FILE_ADD_SUBFOLDER"]).get_aces() == []:
                    self.replaceable_set = 1
                    self.replaceable = 1
                    return 1

        # Recursive check of parent directories
        # 0: A file/dir can be replaced if it's parent dir can be replaced (doesn't really count as it's a recursive definition)
        if self.get_parent_dir() and self.get_parent_dir().get_name() != self.get_name(): # "\" has parent of "\"
            if self.get_parent_dir().is_replaceable():
                self.replaceable_set = 1
                self.replaceable = 1
                return 1

        # File/dir is not replaceable if we get this far
        self.replaceable_set = 1
        self.replaceable = 0

        # print "[D] is_replaceable returning 0 for %s " % self.get_name()
        return 0

    # Doesn't return a trailing slash
    def get_parent_dir(self):
        #print "get_parent_dir called for: " + self.get_name()
        if not self.parent_dir:
            mypath = self.get_name()
            # Check there is a parent dir - e.g. there isn't for "C:"
            if not len(mypath) == 3:  # "c:\"
                parentpath = "\\".join(mypath.split("\\")[0:-2]) + "\\"
                # We frequently refer to parent dirs, so must cache and work we do
                self.parent_dir = wpc.conf.cache.File(parentpath)
        #        print self.parent_dir
            else:
        #        print "[D] no parent dir"
                self.parent_dir = None
        #if self.parent_dir:
            #print "get_parent_dir returning: " + str(self.parent_dir.get_name())
        #else:
            #print "get_parent_dir returning: None"
        return self.parent_dir

    def get_sd(self):
        if self.sd is None:
            #sd = None
            try:
                sd = self.sd = win32security.GetNamedSecurityInfo(
                    self.get_name(),
                    win32security.SE_FILE_OBJECT,
                    win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
                )
                if self.is_dir():
                    self.sd = wpc.conf.cache.sd('directory', sd)
                else:
                    self.sd = wpc.conf.cache.sd('file', sd)
            except:
                print "WARNING: Can't get security descriptor for file: " + self.get_name()
                self.sd = None

        return self.sd