import ctypes
import win32con
import sys
from binascii import hexlify
import win32security
import wpc.conf
import win32event
from wpc.sd import sd

# TODO
# Give perms correct names
# figure out which ones are dangerous
# figure out a way of moving the "s" code in to a function

HANDLE = ctypes.c_ulong
ULONG = ctypes.c_ulong
USHORT = ctypes.c_ushort
PUNICODE_STRING = LPCWSTR = LPWSTR = PWSTR = ctypes.c_wchar_p
PSTR = ctypes.c_char_p
PVOID = LPCVOID = LPVOID = ctypes.c_void_p

class UNICODE_STRING(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("Length", USHORT),
        ("MaximumLength", USHORT),
        ("Buffer", PVOID)
    ]

class OBJECT_ATTRIBUTES(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("Length", ULONG),
        ("RootDirectory", HANDLE),
        ("ObjectName", PUNICODE_STRING),
        ("Attributes", ULONG),
        ("SecurityDescriptor", ULONG),
        ("SecurityQualityOfService", ULONG)
    ]
    
# http://msdn.microsoft.com/en-us/library/bb470234(v=vs.85).aspx
#NTSTATUS WINAPI NtOpenDirectoryObject(
#  _Out_  PHANDLE DirectoryHandle,
#  _In_   ACCESS_MASK DesiredAccess,
#  _In_   POBJECT_ATTRIBUTES ObjectAttributes
#);

NtOpenDirectoryObject = ctypes.windll.ntdll.NtOpenDirectoryObject

# http://msdn.microsoft.com/en-us/library/windows/hardware/ff567029(v=vs.85).aspx
#NTSTATUS ZwOpenSection(    # and also NtOpenSection
#  _Out_  PHANDLE SectionHandle,
#  _In_   ACCESS_MASK DesiredAccess,
#  _In_   POBJECT_ATTRIBUTES ObjectAttributes
#);

NtOpenSection = ctypes.windll.ntdll.NtOpenSection

#http://msdn.microsoft.com/en-us/library/bb470236(v=vs.85).aspx
#NTSTATUS WINAPI NtOpenSymbolicLinkObject(
#  _Out_  PHANDLE LinkHandle,
#  _In_   ACCESS_MASK DesiredAccess,
#  _In_   POBJECT_ATTRIBUTES ObjectAttributes
#);

NtOpenSymbolicLinkObject = ctypes.windll.ntdll.NtOpenSymbolicLinkObject

#http://msdn.microsoft.com/en-us/library/windows/hardware/ff567014(v=vs.85).aspx
#NTSTATUS ZwOpenKey(
#  _Out_  PHANDLE KeyHandle,
#  _In_   ACCESS_MASK DesiredAccess,
#  _In_   POBJECT_ATTRIBUTES ObjectAttributes
#);

NtOpenKey = ctypes.windll.ntdll.NtOpenKey
NtOpenFile = ctypes.windll.ntdll.NtOpenFile
NtOpenEvent = ctypes.windll.ntdll.NtOpenEvent
NtOpenSemaphore = ctypes.windll.ntdll.NtOpenSemaphore 
NtOpenTimer = ctypes.windll.ntdll.NtOpenTimer
NtOpenMutant = ctypes.windll.ntdll.NtOpenMutant

# http://msdn.microsoft.com/en-us/library/bb470238(v=vs.85).aspx
#NTSTATUS WINAPI NtQueryDirectoryObject(
#  _In_       HANDLE DirectoryHandle,
#  _Out_opt_  PVOID Buffer, A pointer to a buffer that receives the directory information. This buffer receives one or more OBJECT_DIRECTORY_INFORMATION structures, the last one being NULL, followed by strings that contain the names of the directory entries. 
#  _In_       ULONG Length,
#  _In_       BOOLEAN ReturnSingleEntry,
#  _In_       BOOLEAN RestartScan,
#  _Inout_    PULONG Context,
#  _Out_opt_  PULONG ReturnLength
#);

NtQueryDirectoryObject = ctypes.windll.ntdll.NtQueryDirectoryObject

# BOOL WINAPI GetKernelObjectSecurity(
#   _In_       HANDLE Handle,
#   _In_       SECURITY_INFORMATION RequestedInformation,
#   _Out_opt_  PSECURITY_DESCRIPTOR pSecurityDescriptor,
#   _In_       DWORD nLength,
#   _Out_      LPDWORD lpnLengthNeeded
# );

# GetKernelObjectSecurity = ctypes.windll.advapi32.GetKernelObjectSecurity 



# typedef struct _OBJECT_DIRECTORY_INFORMATION {
#    UNICODE_STRING Name;
#    UNICODE_STRING TypeName;
# } OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

# TODO

#def is_unicode(s):
#    print "is_unicode: passed %s" % repr(s)
#    if len(s) == 1:
#        print "is_unicode: returning 0"
#        return 0
#    for i in range(0,len(s) - 1, 2):
#        if s[i] != "\x00":
#            print "is_unicode: returning 0"
#            return 0
#    print "is_unicode: returning 1"
#    return 1

#def from_unicode(s):
#    print "from_unicode: passed %s" % repr(s)
#    tmp = ""
#    for i in range(0,len(s) - 1, 2):
#        tmp = tmp + s[i]
#    print "from_unicode: returning %s" % repr(tmp)
#    return tmp
def get_unicode_null(ansi_str):
    tmp = ""
    for c in ansi_str:
        tmp = tmp + c + "\x00"
    tmp = tmp + "\x00\x00"
    return tmp
def get_uni_string_struct(s, uni_string):
    
    #s = UNICODE_STRING()
    s.Length = len(uni_string) * 2
    s.MaximumLength = len(uni_string) * 2 + 2
    print "path: %s" % uni_string
    path_unicode_null = ctypes.create_string_buffer(s.MaximumLength)

    tmp = get_unicode_null(uni_string)

    print "tmp: %s" % repr(tmp)
    fit = min(len(tmp), s.MaximumLength)
    print "fit: %s" % fit
    ctypes.memmove(ctypes.addressof(path_unicode_null), tmp, fit)

    print "1: %s" % repr(path_unicode_null.raw)
    s.Buffer = ctypes.addressof(path_unicode_null)
    print "2: %s" % repr(path_unicode_null)
    print "3: %s" % repr(s.Buffer)
    print "Blengh: %s" % s.Length
    print "Bmaxlengh: %s" % s.MaximumLength
    print "Abuffer: %s" % repr(ctypes.cast(s.Buffer, PWSTR).value)
    #print "Bbuffer: %s%s%s%s" % (s.Buffer[0], s.Buffer[1], s.Buffer[2], s.Buffer[3])
    print s
    return ctypes.addressof(s)
class ntobj:
    def __init__(self, path, objtype=None):
        self.sd = None
        self.path = None
        self.objtype = None
        self.objh = None
        self.set_path(path)
        self.set_type(objtype)
        self.parent_obj = None

    def set_path(self, path):
        self.path = path.encode("utf-8")
        #if is_unicode(path):
        #    self.path = from_unicode(path)
        #else:
        #    self.path = path

    def get_path(self):
        return self.path

    def type_is_implemented(self):
        if (self.get_type() == "Semaphore" or self.get_type() == "Event" or self.get_type() == "Mutant" or self.get_type() == "Timer" or self.get_type() == "Section"  or self.get_type() == "Device" or self.get_type() == "SymbolicLink" or self.get_type() == "Key" or self.get_type() == "Directory"):
            return 1
        return 0
    
    def get_path_unicode_null(self):
        tmp = ""
        for c in self.get_path():
            tmp = tmp + c + "\x00"
        tmp = tmp + "\x00\x00"
        return tmp

    def set_type(self, objtype):
        if objtype:
            self.objtype = objtype.encode("utf-8")
            if objtype.lower() == "key":
                self.objtype = "regkey"

    def get_type(self):
        if not self.objtype:
            self.set_type('Directory')
        return self.objtype

    def as_text(self):
        s = "%s (%s)" % (self.get_name(), self.get_type())
        #if self.get_sd():
        #    s += self.get_sd().as_text()
        #else:
        #    s += "[ERROR]"
        return s

    def get_dangerous_aces(self):
        try:
            #print "[D] File: " + self.get_name()
            #print "[D] ACE: "
            #for a in self.get_sd().get_acelist().get_dangerous_perms().get_aces():
            #    print a.as_text()
            return self.get_sd().get_acelist().get_untrusted().get_dangerous_perms().get_aces()
        except:
            return []

    def get_sd(self):
        import pywintypes
        handle = None
        try:
            handle = self.get_objh()
        except pywintypes.error as e:
            #print "get_sd: can't get handle"
            print "[E] %s: %s" % (e[1], e[2])
            return 0
        #print "get_sd handle: %s" % handle
        s = None
        try:
            s = win32security.GetKernelObjectSecurity(self.get_objh(), win32security.OWNER_SECURITY_INFORMATION | win32security.GROUP_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
            #print "type: %s" % self.get_type().lower()
            t = self.get_type().lower()
            if t == "directory":
                t = "directory_object"
            s = sd(t, s)
        except:
            pass
            # print "[E] can't get sd"
            
        # print "get_sd: %s" % s
        return s

    def get_parent_obj(self):
        if not self.parent_obj:
            mypath = self.get_name()
            # Check there is a parent_obj dir - e.g. there isn't for "Hobj_LOCAL_MACHINE"
            if not mypath.find("\\") == -1:
                # check if only slash is at end of string: "Hobj_LOCAL_MACHINE\"
                if mypath.find("\\") == len(mypath) - 1:
                    self.parent_obj = None
                else:
                    parent_objpath = "\\".join(mypath.split("\\")[0:-1])
                    # We frequently refer to parent_obj dirs, so must cache and work we do
                    self.parent_obj = wpc.conf.cache.regobj(parent_objpath)
            else:
                self.parent_obj = None
        return self.parent_obj

    def dump(self):
        print self.as_text()

    # BUG: sometimes we pass ANSI and sometimes UNICODE.  UNICODE fails because we add extra zeros
    def get_objh(self):
        if not self.objh:
            if self.get_type() == None or self.get_type() == "Directory":
                s = UNICODE_STRING()
                s.Length = len(self.get_path()) * 2
                s.MaximumLength = len(self.get_path()) * 2 + 2
                #print "Apath: %s" % self.get_path()
                path_unicode_null = ctypes.create_string_buffer(s.MaximumLength)
    
                tmp = self.get_path_unicode_null()
    
                #print "Atmp: %s" % repr(tmp)
                fit = min(len(tmp), s.MaximumLength)
                #print "Afit: %s" % fit
                ctypes.memmove(ctypes.addressof(path_unicode_null), tmp, fit)
    
                #print "A1: %s" % repr(path_unicode_null.raw)
                s.Buffer = ctypes.addressof(path_unicode_null)
                #print "A2: %s" % repr(path_unicode_null)
                #print "A3: %s" % repr(s.Buffer)
                #print "Alengh: %s" % s.Length
                #print "Amaxlengh: %s" % s.MaximumLength
                #print "Abuffer: %s" % repr(ctypes.cast(s.Buffer, PWSTR).value)
                #print s
                #t = UNICODE_STRING()
                #address_of_s = get_uni_string_struct(t, self.get_path())
                #print s
                zero = ctypes.c_uint32(0)
                handle = ctypes.c_uint32(0)
                #print "As.Buffer: %s %s" % (repr(ctypes.cast(s.Buffer, PVOID).value[0]), repr(ctypes.cast(s.Buffer, PSTR).value[0])) 
                o = OBJECT_ATTRIBUTES()
                o.Length = ctypes.sizeof(o)
                o.RootDirectory = ctypes.c_uint32(0)
                o.ObjectName = ctypes.addressof(s)
#                o.ObjectName = ctypes.addressof(t)
#                o.ObjectName = address_of_s
                o.Attributes  = 0x00000040
                o.SecurityDescriptor  = ctypes.c_uint32(0)
                o.SecurityQualityOfService  = ctypes.c_uint32(0)
    
                #print "o.ObjectName: %s" % s.Buffer
                ctypes_objh = ctypes.c_uint32(0)
                desired_access = ctypes.c_int(0x00020001)
                ret = NtOpenDirectoryObject(ctypes.addressof(ctypes_objh), desired_access, ctypes.addressof(o))
                if ret == 0:
                    self.objh = ctypes_objh.value
                else:
                    pass
                    #print "return status for NtOpenDirectoryObject: %s (0 = success, non-zero = error)" % ret
            elif self.get_type() == "Section":
                s = UNICODE_STRING()
                s.Length = len(self.get_path()) * 2
                s.MaximumLength = len(self.get_path()) * 2 + 2
                #print "Apath: %s" % self.get_path()
                path_unicode_null = ctypes.create_string_buffer(s.MaximumLength)
    
                tmp = self.get_path_unicode_null()
    
                #print "Atmp: %s" % repr(tmp)
                fit = min(len(tmp), s.MaximumLength)
                #print "Afit: %s" % fit
                ctypes.memmove(ctypes.addressof(path_unicode_null), tmp, fit)
    
                #print "A1: %s" % repr(path_unicode_null.raw)
                s.Buffer = ctypes.addressof(path_unicode_null)
                #print "A2: %s" % repr(path_unicode_null)
                #print "A3: %s" % repr(s.Buffer)
                #print "Alengh: %s" % s.Length
                #print "Amaxlengh: %s" % s.MaximumLength
                #print "Abuffer: %s" % repr(ctypes.cast(s.Buffer, PWSTR).value)
                #print s
                #t = UNICODE_STRING()
                #address_of_s = get_uni_string_struct(t, self.get_path())
                #print s
                zero = ctypes.c_uint32(0)
                handle = ctypes.c_uint32(0)
                #print "As.Buffer: %s %s" % (repr(ctypes.cast(s.Buffer, PVOID).value[0]), repr(ctypes.cast(s.Buffer, PSTR).value[0])) 
                o = OBJECT_ATTRIBUTES()
                o.Length = ctypes.sizeof(o)
                o.RootDirectory = ctypes.c_uint32(0)
                o.ObjectName = ctypes.addressof(s)
#                o.ObjectName = ctypes.addressof(t)
#                o.ObjectName = address_of_s
                o.Attributes  = 0x00000040
                o.SecurityDescriptor  = ctypes.c_uint32(0)
                o.SecurityQualityOfService  = ctypes.c_uint32(0)
    
                #print "o.ObjectName: %s" % s.Buffer
                ctypes_objh = ctypes.c_uint32(0)
                desired_access = ctypes.c_int(0x00020001)
                ret = NtOpenSection(ctypes.addressof(ctypes_objh), desired_access, ctypes.addressof(o))
                if ret == 0:
                    self.objh = ctypes_objh.value
                else:
                    pass
                    #print "return status for NtOpenSection: %s (0 = success, non-zero = error)" % ret
            elif self.get_type() == "SymbolicLink":
                s = UNICODE_STRING()
                s.Length = len(self.get_path()) * 2
                s.MaximumLength = len(self.get_path()) * 2 + 2
                #print "Apath: %s" % self.get_path()
                path_unicode_null = ctypes.create_string_buffer(s.MaximumLength)
    
                tmp = self.get_path_unicode_null()
    
                #print "Atmp: %s" % repr(tmp)
                fit = min(len(tmp), s.MaximumLength)
                #print "Afit: %s" % fit
                ctypes.memmove(ctypes.addressof(path_unicode_null), tmp, fit)
    
                #print "A1: %s" % repr(path_unicode_null.raw)
                s.Buffer = ctypes.addressof(path_unicode_null)
                #print "A2: %s" % repr(path_unicode_null)
                #print "A3: %s" % repr(s.Buffer)
                #print "Alengh: %s" % s.Length
                #print "Amaxlengh: %s" % s.MaximumLength
                #print "Abuffer: %s" % repr(ctypes.cast(s.Buffer, PWSTR).value)
                #print s
                #t = UNICODE_STRING()
                #address_of_s = get_uni_string_struct(t, self.get_path())
                #print s
                zero = ctypes.c_uint32(0)
                handle = ctypes.c_uint32(0)
                #print "As.Buffer: %s %s" % (repr(ctypes.cast(s.Buffer, PVOID).value[0]), repr(ctypes.cast(s.Buffer, PSTR).value[0])) 
                o = OBJECT_ATTRIBUTES()
                o.Length = ctypes.sizeof(o)
                o.RootDirectory = ctypes.c_uint32(0)
                o.ObjectName = ctypes.addressof(s)
#                o.ObjectName = ctypes.addressof(t)
#                o.ObjectName = address_of_s
                o.Attributes  = 0x00000040
                o.SecurityDescriptor  = ctypes.c_uint32(0)
                o.SecurityQualityOfService  = ctypes.c_uint32(0)
    
                #print "o.ObjectName: %s" % s.Buffer
                ctypes_objh = ctypes.c_uint32(0)
                desired_access = ctypes.c_int(0x00020001)
                ret = NtOpenSymbolicLinkObject(ctypes.addressof(ctypes_objh), desired_access, ctypes.addressof(o))
                if ret == 0:
                    self.objh = ctypes_objh.value
                else:
                    pass
                    # print "return status for NtOpenSymbolicLinkObject: %s (0 = success, non-zero = error)" % ret
            elif self.get_type() == "Device":
                s = UNICODE_STRING()
                s.Length = len(self.get_path()) * 2
                s.MaximumLength = len(self.get_path()) * 2 + 2
                #print "Apath: %s" % self.get_path()
                path_unicode_null = ctypes.create_string_buffer(s.MaximumLength)
    
                tmp = self.get_path_unicode_null()
    
                #print "Atmp: %s" % repr(tmp)
                fit = min(len(tmp), s.MaximumLength)
                #print "Afit: %s" % fit
                ctypes.memmove(ctypes.addressof(path_unicode_null), tmp, fit)
    
                #print "A1: %s" % repr(path_unicode_null.raw)
                s.Buffer = ctypes.addressof(path_unicode_null)
                #print "A2: %s" % repr(path_unicode_null)
                #print "A3: %s" % repr(s.Buffer)
                #print "Alengh: %s" % s.Length
                #print "Amaxlengh: %s" % s.MaximumLength
                #print "Abuffer: %s" % repr(ctypes.cast(s.Buffer, PWSTR).value)
                #print s
                #t = UNICODE_STRING()
                #address_of_s = get_uni_string_struct(t, self.get_path())
                #print s
                zero = ctypes.c_uint32(0)
                handle = ctypes.c_uint32(0)
                #print "As.Buffer: %s %s" % (repr(ctypes.cast(s.Buffer, PVOID).value[0]), repr(ctypes.cast(s.Buffer, PSTR).value[0])) 
                o = OBJECT_ATTRIBUTES()
                o.Length = ctypes.sizeof(o)
                o.RootDirectory = ctypes.c_uint32(0)
                o.ObjectName = ctypes.addressof(s)
#                o.ObjectName = ctypes.addressof(t)
#                o.ObjectName = address_of_s
                o.Attributes  = 0x00000040
                o.SecurityDescriptor  = ctypes.c_uint32(0)
                o.SecurityQualityOfService  = ctypes.c_uint32(0)
    
                #print "o.ObjectName: %s" % s.Buffer
                ctypes_objh = ctypes.c_uint32(0)
                desired_access = ctypes.c_int(0x80040000)
                IoStatusBlock = ctypes.create_string_buffer(8)
                ShareAccess = 0x00000007
                OpenOptions = 0x00000000
                ret = NtOpenFile(ctypes.addressof(ctypes_objh), desired_access, ctypes.addressof(o), IoStatusBlock, ShareAccess, OpenOptions)
                if ret == 0:
                    self.objh = ctypes_objh.value
                else:
                    pass
                    # print "return status for NtOpenFile: %s (0 = success, non-zero = error)" % ret
            elif self.get_type() == "Key": # TODO: this errors: ValueError: Procedure probably called with not enough arguments (8 bytes missing)
                s = UNICODE_STRING()
                s.Length = len(self.get_path()) * 2
                s.MaximumLength = len(self.get_path()) * 2 + 2
                #print "Apath: %s" % self.get_path()
                path_unicode_null = ctypes.create_string_buffer(s.MaximumLength)
    
                tmp = self.get_path_unicode_null()
    
                #print "Atmp: %s" % repr(tmp)
                fit = min(len(tmp), s.MaximumLength)
                #print "Afit: %s" % fit
                ctypes.memmove(ctypes.addressof(path_unicode_null), tmp, fit)
    
                #print "A1: %s" % repr(path_unicode_null.raw)
                s.Buffer = ctypes.addressof(path_unicode_null)
                #print "A2: %s" % repr(path_unicode_null)
                #print "A3: %s" % repr(s.Buffer)
                #print "Alengh: %s" % s.Length
                #print "Amaxlengh: %s" % s.MaximumLength
                #print "Abuffer: %s" % repr(ctypes.cast(s.Buffer, PWSTR).value)
                #print s
                #t = UNICODE_STRING()
                #address_of_s = get_uni_string_struct(t, self.get_path())
                #print s
                zero = ctypes.c_uint32(0)
                handle = ctypes.c_uint32(0)
                #print "As.Buffer: %s %s" % (repr(ctypes.cast(s.Buffer, PVOID).value[0]), repr(ctypes.cast(s.Buffer, PSTR).value[0])) 
                o = OBJECT_ATTRIBUTES()
                o.Length = ctypes.sizeof(o)
                o.RootDirectory = ctypes.c_uint32(0)
                o.ObjectName = ctypes.addressof(s)
#                o.ObjectName = ctypes.addressof(t)
#                o.ObjectName = address_of_s
                o.Attributes  = 0x00000040
                o.SecurityDescriptor  = ctypes.c_uint32(0)
                o.SecurityQualityOfService  = ctypes.c_uint32(0)
    
                #print "o.ObjectName: %s" % s.Buffer
                ctypes_objh = ctypes.c_uint32(0)
                desired_access = ctypes.c_int(0x00020001)
                ret = NtOpenKey(ctypes.addressof(ctypes_objh), desired_access, ctypes.addressof(o))
                if ret == 0:
                    self.objh = ctypes_objh.value
                else:
                    pass
                    # print "return status for NtOpenKey: %s (0 = success, non-zero = error)" % ret
            elif self.get_type() == "Semaphore":
                #self.objh = win32event.OpenSemaphore(0x00020000, True, self.get_name_no_path()) # BUG: only works for objects in \BaseNamedObjects
                s = UNICODE_STRING()
                s.Length = len(self.get_path()) * 2
                s.MaximumLength = len(self.get_path()) * 2 + 2
                path_unicode_null = ctypes.create_string_buffer(s.MaximumLength)
    
                tmp = self.get_path_unicode_null()
    
                fit = min(len(tmp), s.MaximumLength)
                ctypes.memmove(ctypes.addressof(path_unicode_null), tmp, fit)
    
                s.Buffer = ctypes.addressof(path_unicode_null)
                zero = ctypes.c_uint32(0)
                handle = ctypes.c_uint32(0)
                o = OBJECT_ATTRIBUTES()
                o.Length = ctypes.sizeof(o)
                o.RootDirectory = ctypes.c_uint32(0)
                o.ObjectName = ctypes.addressof(s)
                o.Attributes  = 0x00000040
                o.SecurityDescriptor  = ctypes.c_uint32(0)
                o.SecurityQualityOfService  = ctypes.c_uint32(0)
    
                ctypes_objh = ctypes.c_uint32(0)
                desired_access = ctypes.c_int(0x00020001)
                ret = NtOpenSemaphore(ctypes.addressof(ctypes_objh), desired_access, ctypes.addressof(o))
                if ret == 0:
                    self.objh = ctypes_objh.value
                else:
                    pass
                    #print "return status for NtOpenSemaphore: %s (0 = success, non-zero = error)" % ret
                
            elif self.get_type() == "Event":
                #print "processing event"
                #self.objh = win32event.OpenEvent(0x00020000, False, self.get_name_no_path()) # BUG: only works for objects in \BaseNamedObjects
                s = UNICODE_STRING()
                s.Length = len(self.get_path()) * 2
                s.MaximumLength = len(self.get_path()) * 2 + 2
                #print "Apath: %s" % self.get_path()
                path_unicode_null = ctypes.create_string_buffer(s.MaximumLength)
    
                tmp = self.get_path_unicode_null()
    
                #print "Atmp: %s" % repr(tmp)
                fit = min(len(tmp), s.MaximumLength)
                #print "Afit: %s" % fit
                ctypes.memmove(ctypes.addressof(path_unicode_null), tmp, fit)
    
                #print "A1: %s" % repr(path_unicode_null.raw)
                s.Buffer = ctypes.addressof(path_unicode_null)
                #print "A2: %s" % repr(path_unicode_null)
                #print "A3: %s" % repr(s.Buffer)
                #print "Alengh: %s" % s.Length
                #print "Amaxlengh: %s" % s.MaximumLength
                #print "Abuffer: %s" % repr(ctypes.cast(s.Buffer, PWSTR).value)
                #print s
                #t = UNICODE_STRING()
                #address_of_s = get_uni_string_struct(t, self.get_path())
                #print s
                zero = ctypes.c_uint32(0)
                handle = ctypes.c_uint32(0)
                #print "As.Buffer: %s %s" % (repr(ctypes.cast(s.Buffer, PVOID).value[0]), repr(ctypes.cast(s.Buffer, PSTR).value[0])) 
                o = OBJECT_ATTRIBUTES()
                o.Length = ctypes.sizeof(o)
                o.RootDirectory = ctypes.c_uint32(0)
                o.ObjectName = ctypes.addressof(s)
#                o.ObjectName = ctypes.addressof(t)
#                o.ObjectName = address_of_s
                o.Attributes  = 0x00000040
                o.SecurityDescriptor  = ctypes.c_uint32(0)
                o.SecurityQualityOfService  = ctypes.c_uint32(0)
    
                #print "o.ObjectName: %s" % s.Buffer
                ctypes_objh = ctypes.c_uint32(0)
                desired_access = ctypes.c_int(0x00020001)
                ret = NtOpenEvent(ctypes.addressof(ctypes_objh), desired_access, ctypes.addressof(o))
                if ret == 0:
                    self.objh = ctypes_objh.value
                else:
                    pass
                    #print "return status for NtOpenEvent: %s (0 = success, non-zero = error)" % ret
            elif self.get_type() == "Mutant":
                #self.objh = win32event.OpenMutex(0x00020000, True, self.get_name_no_path()) # BUG: only works for objects in \BaseNamedObjects
                s = UNICODE_STRING()
                s.Length = len(self.get_path()) * 2
                s.MaximumLength = len(self.get_path()) * 2 + 2
                path_unicode_null = ctypes.create_string_buffer(s.MaximumLength)
    
                tmp = self.get_path_unicode_null()
    
                fit = min(len(tmp), s.MaximumLength)
                ctypes.memmove(ctypes.addressof(path_unicode_null), tmp, fit)
    
                s.Buffer = ctypes.addressof(path_unicode_null)
                zero = ctypes.c_uint32(0)
                handle = ctypes.c_uint32(0)
                o = OBJECT_ATTRIBUTES()
                o.Length = ctypes.sizeof(o)
                o.RootDirectory = ctypes.c_uint32(0)
                o.ObjectName = ctypes.addressof(s)
                o.Attributes  = 0x00000040
                o.SecurityDescriptor  = ctypes.c_uint32(0)
                o.SecurityQualityOfService  = ctypes.c_uint32(0)
    
                ctypes_objh = ctypes.c_uint32(0)
                desired_access = ctypes.c_int(0x00020001)
                ret = NtOpenMutant(ctypes.addressof(ctypes_objh), desired_access, ctypes.addressof(o))
                if ret == 0:
                    self.objh = ctypes_objh.value
                else:
                    pass
                    #print "return status for NtOpenMutant: %s (0 = success, non-zero = error)" % ret
            elif self.get_type() == "Timer":
                print "[D] TIMER"
                #self.objh = win32event.OpenWaitableTimer(0x00020000, False, self.get_name_no_path()) # BUG: only works for objects in \BaseNamedObjects
                s = UNICODE_STRING()
                s.Length = len(self.get_path()) * 2
                s.MaximumLength = len(self.get_path()) * 2 + 2
                path_unicode_null = ctypes.create_string_buffer(s.MaximumLength)
    
                tmp = self.get_path_unicode_null()
    
                fit = min(len(tmp), s.MaximumLength)
                ctypes.memmove(ctypes.addressof(path_unicode_null), tmp, fit)
    
                s.Buffer = ctypes.addressof(path_unicode_null)
                zero = ctypes.c_uint32(0)
                handle = ctypes.c_uint32(0)
                o = OBJECT_ATTRIBUTES()
                o.Length = ctypes.sizeof(o)
                o.RootDirectory = ctypes.c_uint32(0)
                o.ObjectName = ctypes.addressof(s)
                o.Attributes  = 0x00000040
                o.SecurityDescriptor  = ctypes.c_uint32(0)
                o.SecurityQualityOfService  = ctypes.c_uint32(0)
    
                ctypes_objh = ctypes.c_uint32(0)
                desired_access = ctypes.c_int(0x00020001)
                ret = NtOpenTimer(ctypes.addressof(ctypes_objh), desired_access, ctypes.addressof(o))
                if ret == 0:
                    self.objh = ctypes_objh.value
                    print "[D] TIMER handle: %s" % self.objh
                else:
                    pass
                    #print "return status for NtOpenTimer: %s (0 = success, non-zero = error)" % ret
                
            else:
                pass
                # print "[E] Don't know how to open a handle to object of type: %s" % self.get_type()
        return self.objh

    def get_child_objects(self, index=0):
        #print "get_child_objects: %s" % self.get_name()
        child_objects = []

        bufflen = 1000
        outbuffer = ctypes.create_string_buffer(bufflen)
        returnsingle = False
        restartscan = False
        #print "index: %s" % index
        context = ctypes.c_int(index)
        retlen = ctypes.c_int(0)
        ret = NtQueryDirectoryObject(self.get_objh(), ctypes.addressof(outbuffer), ctypes.c_int(bufflen-2), returnsingle, restartscan, ctypes.byref(context), ctypes.byref(retlen))
        #print "context: %s" % context
        #print "retlen: %s" % retlen
        def receiveSome(self, bytes):
                fit = min(len(bytes), ctypes.sizeof(self))
                ctypes.memmove(ctypes.addressof(self), bytes, fit)

        object_name = UNICODE_STRING()
        object_type = UNICODE_STRING()

        count = 0
        done = 0
        if retlen.value > 16:
            #print "outbuffer: %s" % repr(outbuffer.raw.replace("\x00", ""))
            while not done:
                receiveSome(object_name, outbuffer.raw[count * 8: (count + 1) * 8])
                receiveSome(object_type, outbuffer.raw[(count + 1) * 8: (count + 2) * 8])
                if object_name.Length:
                    child_objects.append(ntobj(self.get_path().rstrip("\\") + "\\" + ctypes.cast(object_name.Buffer, PWSTR).value, ctypes.cast(object_type.Buffer, PWSTR).value))
                else:
                    done = 1
                count = count + 2
            extra_child_objects = self.get_child_objects(context.value)
            for c in extra_child_objects:
                child_objects.append(c)
            
        return child_objects

    def get_all_child_objects(self):
        #print "get_all_child_objects: %s" % self.get_name()
        if self.get_type() is None or self.get_type() == "Directory":
            for obj in self.get_child_objects():
                yield obj
                for k in obj.get_all_child_objects():
                    yield k

    def get_name(self):
        return self.get_path()

    def get_name_no_path(self):
        import re
        regex = re.compile("\\\\([^\\\\]*)$")
        m = regex.search(self.get_path())
        if m:
            #print "get_name_no_path returning: %s" % m.group(1)
            return m.group(1)
        else:
            print "get_name_no_path returning null for: %s" % self.get_path()
            return None

    def as_tab(self, dangerous_only=1):
        lines = []
        lines.append(wpc.utils.tab_line("info", self.get_type(), str(self.get_name())))
        if self.get_sd():
            lines.append(wpc.utils.tab_line("gotsd", self.get_type(), str(self.get_name()), "yes"))
            lines.append(wpc.utils.tab_line("owner", self.get_type(), str(self.get_name()), str(self.get_sd().get_owner().get_fq_name())))         
            if self.get_sd().has_dacl():
                lines.append(wpc.utils.tab_line("hasdacl", self.get_type(), str(self.get_name()), "yes"))
                if dangerous_only:
                    lines.extend(self.get_sd().dangerous_aces_as_tab("ace", self.get_type(), str(self.get_name())))
                else:
                    lines.extend(self.get_sd().aces_as_tab("ace", self.get_type(), str(self.get_name())))
            else:
                lines.append(wpc.utils.tab_line("hasdacl", self.get_type(), str(self.get_name()), "no"))
        else:
            lines.append(wpc.utils.tab_line("gotsd", self.get_type(), str(self.get_name()), "no"))
        #print lines
        return "\n".join(lines)