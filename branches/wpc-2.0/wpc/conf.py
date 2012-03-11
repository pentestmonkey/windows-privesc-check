# Not a class, just a bunch of constants
import _winreg
import ntsecuritycon
import win32con
import win32netcon
import win32service

remote_server = None
executable_file_extensions = ('exe', 'com', 'bat', 'dll', 'pl', 'rb', 'py', 'php', 'inc', 'asp', 'aspx', 'ocx', 'vbs')
version = None
cache = None
on64bitwindows = None

kb_nos = {
        '977165': 'MS10_015 Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (kitrap0d - meterpreter "getsystem")',
        '828749': 'MS03_049 Microsoft Workstation Service NetAddAlternateComputerName Overflow (netapi)     ',
        '828028': 'MS04_007 Microsoft ASN.1 Library Bitstring Heap Overflow (killbill)      ',
        '835732': 'MS04_011 Microsoft LSASS Service DsRolerUpgradeDownlevelServer Overflow (lsass)    ',
        '841533': 'MS04_031 Microsoft NetDDE Service Overflow (netdde)',
        '899588': 'MS05_039 Microsoft Plug and Play Service Overflow (pnp)',
        '911280': 'MS06_025 Microsoft RRAS Service RASMAN Registry Overflow (rasmans_reg)',
        '911280': 'MS06_025 Microsoft RRAS Service Overflow (rras)',
        '921883': 'MS06_040 Microsoft Server Service NetpwPathCanonicalize Overflow (netapi)',
        '923980': 'MS06_066 Microsoft Services MS06-066 nwapi32.dll (nwapi)',
        '923980': 'MS06_066 Microsoft Services MS06-066 nwwks.dll (nwwks)',
        '924270': 'MS06_070 Microsoft Workstation Service NetpManageIPCConnect Overflow (wkssvc)',
        '935966': 'MS07_029 Microsoft DNS RPC Service extractQuotedChar() Overflow (SMB) (msdns_zonename)',
        '958644': 'MS08_067 Microsoft Server Service Relative Path Stack Corruption (netapi)',
        '975517': 'MS09_050 Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference (smb2_negotiate_func_index)',
        '823980': 'MS03_026 Microsoft RPC DCOM Interface Overflow',
        '892944': 'MS05_017 Microsoft Message Queueing Service Path Overflow',
        '937894': 'MS07_065 Microsoft Message Queueing Service DNS Name Path Overflow'
}

reg_paths = (
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services',
#    'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell',
    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit',
    'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce',
#    'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices',
    'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce',
#    'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices',
#    'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce',
#    'HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows',
)

# We don't care if some users / groups hold dangerous permission because they're trusted
# These have fully qualified names:
trusted_principals_fq = [
    "BUILTIN\\Administrators",
    "NT SERVICE\\TrustedInstaller",
    "NT AUTHORITY\\SYSTEM"
]

# We don't care if members of these groups hold dangerous permission because they're trusted
# These have names without a domain:
#trusted_principals = (
    #"Administrators",
    #"Domain Admins",
    #"Enterprise Admins",
#)
trusted_principals = []

eventlog_key_hklm = 'SYSTEM\CurrentControlSet\Services\Eventlog'

# Windows privileges from 
windows_privileges = (
        "SeAssignPrimaryTokenPrivilege",
        "SeBackupPrivilege",
        "SeCreatePagefilePrivilege",
        "SeCreateTokenPrivilege",
        "SeDebugPrivilege",
        "SeEnableDelegationPrivilege",
        "SeLoadDriverPrivilege",
        "SeMachineAccountPrivilege",
        "SeManageVolumePrivilege",
        "SeRelabelPrivilege",
        "SeRestorePrivilege",
        "SeShutdownPrivilege",
        "SeSyncAgentPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeTcbPrivilege",
        "SeTrustedCredManAccessPrivilege",
        "SeSecurityPrivilege",
        "SeRemoteShutdownPrivilege",
        "SeProfileSingleProcessPrivilege",
        "SeAuditPrivilege",
        "SeIncreaseBasePriorityPrivilege",
        "SeIncreaseWorkingSetPrivilege",
        "SeIncreaseQuotaPrivilege",
        "SeLockMemoryPrivilege",
        "SeSystemEnvironmentPrivilege",
        "SeChangeNotifyPrivilege",
        "SeCreateGlobalPrivilege",
        "SeCreatePermanentPrivilege",
        "SeCreateSymbolicLinkPrivilege",
        "SeImpersonatePrivilege",
        "SeSystemProfilePrivilege",
        "SeSystemtimePrivilege",
        "SeTimeZonePrivilege",
        "SeUndockPrivilege",
        "SeUnsolicitedInputPrivilege",
        "SeBatchLogonRight",
        "SeDenyBatchLogonRight",
        "SeDenyInteractiveLogonRight",
        "SeDenyNetworkLogonRight",
        "SeDenyRemoteInteractiveLogonRight",
        "SeDenyServiceLogonRight",
        "SeInteractiveLogonRight",
        "SeNetworkLogonRight",
        "SeRemoteInteractiveLogonRight",
        "SeServiceLogonRight"
)

share_types = (
    "STYPE_IPC",
    "STYPE_DISKTREE",
    "STYPE_PRINTQ",
    "STYPE_DEVICE",
)

sv_types = (
        "SV_TYPE_WORKSTATION",
        "SV_TYPE_SERVER",
        "SV_TYPE_SQLSERVER",
        "SV_TYPE_DOMAIN_CTRL",
        "SV_TYPE_DOMAIN_BAKCTRL",
        "SV_TYPE_TIME_SOURCE",
        "SV_TYPE_AFP",
        "SV_TYPE_NOVELL",
        "SV_TYPE_DOMAIN_MEMBER",
        "SV_TYPE_PRINTQ_SERVER",
        "SV_TYPE_DIALIN_SERVER",
        "SV_TYPE_XENIX_SERVER",
        "SV_TYPE_NT",
        "SV_TYPE_WFW",
        "SV_TYPE_SERVER_MFPN",
        "SV_TYPE_SERVER_NT",
        "SV_TYPE_POTENTIAL_BROWSER",
        "SV_TYPE_BACKUP_BROWSER",
        "SV_TYPE_MASTER_BROWSER",
        "SV_TYPE_DOMAIN_MASTER",
        "SV_TYPE_SERVER_OSF",
        "SV_TYPE_SERVER_VMS",
        "SV_TYPE_WINDOWS",
        "SV_TYPE_DFS",
        "SV_TYPE_CLUSTER_NT",
        "SV_TYPE_TERMINALSERVER",  # missing from win32netcon.py
        #"SV_TYPE_CLUSTER_VS_NT",  # missing from win32netcon.py
        "SV_TYPE_DCE",
        "SV_TYPE_ALTERNATE_XPORT",
        "SV_TYPE_LOCAL_LIST_ONLY",
        "SV_TYPE_DOMAIN_ENUM"
)

win32netcon.SV_TYPE_TERMINALSERVER = 0x2000000 

sid_is_group_type = {
    ntsecuritycon.SidTypeUser: 0,
    ntsecuritycon.SidTypeGroup: 1,
    ntsecuritycon.SidTypeDomain: 0,
    ntsecuritycon.SidTypeAlias: 1,
    ntsecuritycon.SidTypeWellKnownGroup: 1,
    ntsecuritycon.SidTypeDeletedAccount: 0,
    ntsecuritycon.SidTypeInvalid: 0,
    ntsecuritycon.SidTypeUnknown: 0,
    ntsecuritycon.SidTypeComputer: 0,
    ntsecuritycon.SidTypeLabel: 0
}

sid_type = {
    ntsecuritycon.SidTypeUser: "user",
    ntsecuritycon.SidTypeGroup: "group",
    ntsecuritycon.SidTypeDomain: "domain",
    ntsecuritycon.SidTypeAlias: "alias",
    ntsecuritycon.SidTypeWellKnownGroup: "wellknowngroup",
    ntsecuritycon.SidTypeDeletedAccount: "deletedaccount",
    ntsecuritycon.SidTypeInvalid: "invalid",
    ntsecuritycon.SidTypeUnknown: "unknown",
    ntsecuritycon.SidTypeComputer: "computer",
    ntsecuritycon.SidTypeLabel: "label"
}

dangerous_perms_write = {
    # http://www.tek-tips.com/faqs.cfm?fid
    'share': {
        ntsecuritycon: (
            "FILE_READ_DATA",
            "FILE_WRITE_DATA",
            "FILE_APPEND_DATA",
            "FILE_READ_EA",
            "FILE_WRITE_EA",
            "FILE_EXECUTE",
            "FILE_READ_ATTRIBUTES",
            "FILE_WRITE_ATTRIBUTES",
            "DELETE",
            "READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            "SYNCHRONIZE",
        )
    },
    'file': {
        ntsecuritycon: (
            #"FILE_READ_DATA",
            "FILE_WRITE_DATA",
            "FILE_APPEND_DATA",  # probably not dangerous for .exe files, but could be dangerous for .bat (or other script) files
            #"FILE_READ_EA",
            #"FILE_WRITE_EA",
            #"FILE_EXECUTE",
            #"FILE_READ_ATTRIBUTES",
            #"FILE_WRITE_ATTRIBUTES",
            "DELETE",
            #"READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            #"SYNCHRONIZE",
        )
    },
    # http://msdn.microsoft.com/en-us/library/ms724878(VS.85).aspx
    # KEY_ALL_ACCESS: STANDARD_RIGHTS_REQUIRED KEY_QUERY_VALUE KEY_SET_VALUE KEY_CREATE_SUB_KEY KEY_ENUMERATE_SUB_KEYS KEY_NOTIFY KEY_CREATE_LINK
    # KEY_CREATE_LINK (0x0020) Reserved for system use.
    # KEY_CREATE_SUB_KEY (0x0004)    Required to create a subkey of a registry key.
    # KEY_ENUMERATE_SUB_KEYS (0x0008)    Required to enumerate the subkeys of a registry key.
    # KEY_EXECUTE (0x20019)    Equivalent to KEY_READ.
    # KEY_NOTIFY (0x0010)    Required to request change notifications for a registry key or for subkeys of a registry key.
    # KEY_QUERY_VALUE (0x0001)    Required to query the values of a registry key.
    # KEY_READ (0x20019)    Combines the STANDARD_RIGHTS_READ, KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, and KEY_NOTIFY values.
    # KEY_SET_VALUE (0x0002)    Required to create, delete, or set a registry value.
    # KEY_WOW64_32KEY (0x0200)    Indicates that an application on 64-bit Windows should operate on the 32-bit registry view. For more information, see Accessing an Alternate Registry View.    This flag must be combined using the OR operator with the other flags in this table that either query or access registry values.
    # Windows 2000:  This flag is not supported.
    # KEY_WOW64_64KEY (0x0100)    Indicates that an application on 64-bit Windows should operate on the 64-bit registry view. For more information, see Accessing an Alternate Registry View.
    # This flag must be combined using the OR operator with the other flags in this table that either query or access registry values.
    # Windows 2000:  This flag is not supported.
    # KEY_WRITE (0x20006)    Combines the STANDARD_RIGHTS_WRITE, KEY_SET_VALUE, and KEY_CREATE_SUB_KEY access rights.
    # "STANDARD_RIGHTS_REQUIRED",
    # "STANDARD_RIGHTS_WRITE",
    # "STANDARD_RIGHTS_READ",
    # "DELETE",
    # "READ_CONTROL",
    # "WRITE_DAC",
    #"WRITE_OWNER",
    'regkey': {        
        _winreg: (
            #"KEY_ALL_ACCESS",  # Combines the STANDARD_RIGHTS_REQUIRED, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, and KEY_CREATE_LINK access rights.
            #"KEY_QUERY_VALUE", # GUI "Query Value"
            "KEY_SET_VALUE",  # GUI "Set Value".  Required to create, delete, or set a registry value.
            "KEY_CREATE_LINK",  # GUI "Create Link".  Reserved for system use.
            "KEY_CREATE_SUB_KEY",  # GUI "Create subkey"
            # "KEY_ENUMERATE_SUB_KEYS",  # GUI "Create subkeys"
            # "KEY_NOTIFY", # GUI "Notify"
            #"KEY_EXECUTE", # same as KEY_READ
            #"KEY_READ",
            #"KEY_WOW64_32KEY",
            #"KEY_WOW64_64KEY",
            # "KEY_WRITE", # Combines the STANDARD_RIGHTS_WRITE, KEY_SET_VALUE, and KEY_CREATE_SUB_KEY access rights.
        ),
        ntsecuritycon: (
            "DELETE",  # GUI "Delete"
            # "READ_CONTROL", # GUI "Read Control" - read security descriptor
            "WRITE_DAC",  # GUI "Write DAC"
            "WRITE_OWNER",  # GUI "Write Owner"
            #"STANDARD_RIGHTS_REQUIRED",
            #"STANDARD_RIGHTS_WRITE",
            #"STANDARD_RIGHTS_READ",
        )
    },
    'directory': {
        ntsecuritycon: (
            #"FILE_LIST_DIRECTORY",
            "FILE_ADD_FILE",
            "FILE_ADD_SUBDIRECTORY",
            #"FILE_READ_EA",
            "FILE_WRITE_EA",
            #"FILE_TRAVERSE",
            "FILE_DELETE_CHILD",
            #"FILE_READ_ATTRIBUTES",
            "FILE_WRITE_ATTRIBUTES",
            "DELETE",
            #"READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            #"SYNCHRONIZE",
        )
    },
    'service_manager': {
        # For service manager
        # http://msdn.microsoft.com/en-us/library/ms685981(VS.85).aspx
        # SC_MANAGER_ALL_ACCESS (0xF003F)    Includes STANDARD_RIGHTS_REQUIRED, in addition to all access rights in this table.
        # SC_MANAGER_CREATE_SERVICE (0x0002)    Required to call the CreateService function to create a service object and add it to the database.
        # SC_MANAGER_CONNECT (0x0001)    Required to connect to the service control manager.
        # SC_MANAGER_ENUMERATE_SERVICE (0x0004)    Required to call the EnumServicesStatusEx function to list the services that are in the database.
        # SC_MANAGER_LOCK (0x0008)    Required to call the LockServiceDatabase function to acquire a lock on the database.
        # SC_MANAGER_MODIFY_BOOT_CONFIG (0x0020)    Required to call the NotifyBootConfigStatus function.
        # SC_MANAGER_QUERY_LOCK_STATUS (0x0010)Required to call the  QueryServiceLockStatus function to retrieve the lock status information for the database.
        win32service: (
            "SC_MANAGER_ALL_ACCESS",
            "SC_MANAGER_CREATE_SERVICE",
            "SC_MANAGER_CONNECT",
            "SC_MANAGER_ENUMERATE_SERVICE",
            "SC_MANAGER_LOCK",
            "SC_MANAGER_MODIFY_BOOT_CONFIG",
            "SC_MANAGER_QUERY_LOCK_STATUS",
        )
    },
    # http://msdn.microsoft.com/en-us/library/ms684880(v=vs.85).aspx
    'process': {
        win32con: (
            "PROCESS_TERMINATE",
            "PROCESS_CREATE_THREAD",
            "PROCESS_VM_OPERATION",
            "PROCESS_VM_READ",
            "PROCESS_VM_WRITE",
            "PROCESS_DUP_HANDLE",
            "PROCESS_CREATE_PROCESS",
            "PROCESS_SET_QUOTA",
            "PROCESS_SET_INFORMATION",
            #"PROCESS_QUERY_INFORMATION",
            #"PROCESS_QUERY_LIMITED_INFORMATION",
            "PROCESS_SUSPEND_RESUME",
            #"PROCESS_ALL_ACCESS"
        ),
        ntsecuritycon: (
            "DELETE",
            #"READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            #"SYNCHRONIZE",
            #"STANDARD_RIGHTS_REQUIRED",
            #"STANDARD_RIGHTS_READ",
            #"STANDARD_RIGHTS_WRITE",
            #"STANDARD_RIGHTS_EXECUTE",
            #"STANDARD_RIGHTS_ALL",
            #"SPECIFIC_RIGHTS_ALL",
            #"ACCESS_SYSTEM_SECURITY",
            #"MAXIMUM_ALLOWED",
            #"GENERIC_READ",
            #"GENERIC_WRITE",
            #"GENERIC_EXECUTE",
            #"GENERIC_ALL"
        )
    },
    'service': {
        # For services:
        # http://msdn.microsoft.com/en-us/library/ms685981(VS.85).aspx
        # SERVICE_ALL_ACCESS (0xF01FF)    Includes STANDARD_RIGHTS_REQUIRED in addition to all access rights in this table.
        # SERVICE_CHANGE_CONFIG (0x0002)    Required to call the ChangeServiceConfig or ChangeServiceConfig2 function to change the service configuration. Because     this grants the caller the right to change the executable file that the system runs, it should be granted only to administrators.
        # SERVICE_ENUMERATE_DEPENDENTS (0x0008)    Required to call the EnumDependentServices function to enumerate all the services dependent on the service.
        # SERVICE_INTERROGATE (0x0080)    Required to call the ControlService function to ask the service to report its status immediately.
        # SERVICE_PAUSE_CONTINUE (0x0040)    Required to call the ControlService function to pause or continue the service.
        # SERVICE_QUERY_CONFIG (0x0001)    Required to call the QueryServiceConfig and QueryServiceConfig2 functions to query the service configuration.
        # SERVICE_QUERY_STATUS (0x0004)    Required to call the QueryServiceStatusEx function to ask the service control manager about the status of the service.
        # SERVICE_START (0x0010)    Required to call the StartService function to start the service.
        # SERVICE_STOP (0x0020)    Required to call the ControlService function to stop the service.
        # SERVICE_USER_DEFINED_CONTROL(0x0100)    Required to call the ControlService function to specify a user-defined control code.
        win32service: (
            # "SERVICE_INTERROGATE",
            # "SERVICE_QUERY_STATUS",
            # "SERVICE_ENUMERATE_DEPENDENTS",
            "SERVICE_ALL_ACCESS",
            "SERVICE_CHANGE_CONFIG",
            "SERVICE_PAUSE_CONTINUE",
            # "SERVICE_QUERY_CONFIG",
            "SERVICE_START",
            "SERVICE_STOP",
            # "SERVICE_USER_DEFINED_CONTROL", # TODO this is granted most of the time.  Double check that's not a bad thing.
        ),
        ntsecuritycon: (
            "DELETE",
            "WRITE_DAC",
            "WRITE_OWNER"
        )
#        win32con: (
#            "READ_CONTROL"
#        )
    },
}

win32con.PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
win32con.PROCESS_SUSPEND_RESUME = 0x0800

all_perms = {
    'share': {
        ntsecuritycon: (
            "FILE_READ_DATA",
            "FILE_WRITE_DATA",
            "FILE_APPEND_DATA",
            "FILE_READ_EA",
            "FILE_WRITE_EA",
            "FILE_EXECUTE",
            "FILE_READ_ATTRIBUTES",
            "FILE_WRITE_ATTRIBUTES",
            "DELETE",
            "READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            "SYNCHRONIZE",
        )
    },
    'file': {
        ntsecuritycon: (
            "FILE_READ_DATA",
            "FILE_WRITE_DATA",
            "FILE_APPEND_DATA",
            "FILE_READ_EA",
            "FILE_WRITE_EA",
            "FILE_EXECUTE",
            "FILE_READ_ATTRIBUTES",
            "FILE_WRITE_ATTRIBUTES",
            "DELETE",
            "READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            "SYNCHRONIZE",
        )
    },
    'regkey': {
        _winreg: (
            #"KEY_ALL_ACCESS",
            "KEY_CREATE_LINK",
            "KEY_CREATE_SUB_KEY",
            "KEY_ENUMERATE_SUB_KEYS",
            #"KEY_EXECUTE", # same as KEY_READ
            "KEY_NOTIFY",
            "KEY_QUERY_VALUE",
            "KEY_READ",
            "KEY_SET_VALUE",
            "KEY_WOW64_32KEY",
            "KEY_WOW64_64KEY",
            #"KEY_WRITE", #STANDARD_RIGHTS_WRITE, KEY_SET_VALUE, and KEY_CREATE_SUB_KEY access rights.
        ),
        ntsecuritycon: (
            "DELETE",
            "READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            #"STANDARD_RIGHTS_REQUIRED",
            #"STANDARD_RIGHTS_WRITE", # same as STANDARD_RIGHTS_READ http://msdn.microsoft.com/en-us/library/aa379607(v=vs.85).aspx what is it for?
            #"STANDARD_RIGHTS_READ", # same as STANDARD_RIGHTS_WRITE http://msdn.microsoft.com/en-us/library/aa379607(v=vs.85).aspx what is it for?
            #"SYNCHRONIZE",
        )
    },
    'directory': {
        ntsecuritycon: (
            "FILE_LIST_DIRECTORY",
            "FILE_ADD_FILE",
            "FILE_ADD_SUBDIRECTORY",
            "FILE_READ_EA",
            "FILE_WRITE_EA",
            "FILE_TRAVERSE",
            "FILE_DELETE_CHILD",
            "FILE_READ_ATTRIBUTES",
            "FILE_WRITE_ATTRIBUTES",
            "DELETE",
            "READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            "SYNCHRONIZE",
        )
    },
    'service_manager': {
        win32service: (
            "SC_MANAGER_ALL_ACCESS",
            "SC_MANAGER_CREATE_SERVICE",
            "SC_MANAGER_CONNECT",
            "SC_MANAGER_ENUMERATE_SERVICE",
            "SC_MANAGER_LOCK",
            "SC_MANAGER_MODIFY_BOOT_CONFIG",
            "SC_MANAGER_QUERY_LOCK_STATUS",
        )
    },
    'service': {
        win32service: (
            "SERVICE_INTERROGATE",
            "SERVICE_QUERY_STATUS",
            "SERVICE_ENUMERATE_DEPENDENTS",
            # "SERVICE_ALL_ACCESS", # combination of other rights
            "SERVICE_CHANGE_CONFIG",
            "SERVICE_PAUSE_CONTINUE",
            "SERVICE_QUERY_CONFIG",
            "SERVICE_START",
            "SERVICE_STOP",
            "SERVICE_USER_DEFINED_CONTROL",  # TODO this is granted most of the time.  Double check that's not a bad thing.
        ),
        ntsecuritycon: (
            "DELETE",
            "READ_CONTROL",  # needed to read acl of service
            "WRITE_DAC",
            "WRITE_OWNER",
            "SYNCHRONIZE",
            #"STANDARD_RIGHTS_REQUIRED", # combination of other rights
            #"STANDARD_RIGHTS_READ", # combination of other rights
            #"STANDARD_RIGHTS_WRITE", # combination of other rights
            #"STANDARD_RIGHTS_EXECUTE", # combination of other rights
            #"STANDARD_RIGHTS_ALL", # combination of other rights
            #"SPECIFIC_RIGHTS_ALL", # combination of other rights
            "ACCESS_SYSTEM_SECURITY",
            #"MAXIMUM_ALLOWED",
            "GENERIC_READ",
            "GENERIC_WRITE",
            "GENERIC_EXECUTE",
            "GENERIC_ALL"
        )
    },
    # http://msdn.microsoft.com/en-us/library/ms684880(v=vs.85).aspx
    'process': {
        win32con: (
            "PROCESS_TERMINATE",
            "PROCESS_CREATE_THREAD",
            "PROCESS_VM_OPERATION",
            "PROCESS_VM_READ",
            "PROCESS_VM_WRITE",
            "PROCESS_DUP_HANDLE",
            "PROCESS_CREATE_PROCESS",
            "PROCESS_SET_QUOTA",
            "PROCESS_SET_INFORMATION",
            "PROCESS_QUERY_INFORMATION",
            "PROCESS_QUERY_LIMITED_INFORMATION",
            "PROCESS_SUSPEND_RESUME",
            #"PROCESS_ALL_ACCESS"
        ),
        ntsecuritycon: (
            "DELETE",
            "READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            "SYNCHRONIZE",
            #"STANDARD_RIGHTS_REQUIRED",
            #"STANDARD_RIGHTS_READ",
            #"STANDARD_RIGHTS_WRITE",
            #"STANDARD_RIGHTS_EXECUTE",
            #"STANDARD_RIGHTS_ALL",
            #"SPECIFIC_RIGHTS_ALL",
            #"ACCESS_SYSTEM_SECURITY",
            #"MAXIMUM_ALLOWED",
            #"GENERIC_READ",
            #"GENERIC_WRITE",
            #"GENERIC_EXECUTE",
            #"GENERIC_ALL"
        )
    },
    'thread': {
        win32con: (
            "THREAD_TERMINATE",
            "THREAD_SUSPEND_RESUME",
            "THREAD_GET_CONTEXT",
            "THREAD_SET_CONTEXT",
            "THREAD_SET_INFORMATION",
            "THREAD_QUERY_INFORMATION",
            "THREAD_SET_THREAD_TOKEN",
            "THREAD_IMPERSONATE",
            "THREAD_DIRECT_IMPERSONATION",
            "THREAD_ALL_ACCESS",
            "THREAD_QUERY_LIMITED_INFORMATION",
            "THREAD_SET_LIMITED_INFORMATION"
        ),
        ntsecuritycon: (
            "DELETE",
            "READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            "SYNCHRONIZE",
        )
    },
    'token': {
        win32con: (
            "TOKEN_ADJUST_DEFAULT",
            "TOKEN_ADJUST_GROUPS",
            "TOKEN_ADJUST_PRIVILEGES",
            #"TOKEN_ADJUST_SESSIONID", TODO what's the number for this?
            "TOKEN_ASSIGN_PRIMARY",
            "TOKEN_DUPLICATE",
            "TOKEN_EXECUTE",
            "TOKEN_IMPERSONATE",
            "TOKEN_QUERY",
            "TOKEN_QUERY_SOURCE",
            "TOKEN_READ",
            "TOKEN_WRITE",
            "TOKEN_ALL_ACCESS"
        ),
        ntsecuritycon: (
            "DELETE",
            "READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            #"SYNCHRONIZE",
        )
    },
}

# Used to store a data structure representing the issues we've found
# We use this to generate the report
issues = {}

issue_template = {
    'WPC001': {
       'title': "Insecure Permissions on Program Files",
       'description': '''Some of the programs in %ProgramFiles% and/or %ProgramFiles(x86)% could be changed by non-administrative users.

This could allow certain users on the system to place malicious code into certain key directories, or to replace programs with malicious ones.  A malicious local user could use this technique to hijack the privileges of other local users, running commands with their privileges.
''',
       'recommendation': '''Programs run by multiple users should only be changable only by administrative users.  The directories containing these programs should only be changable only by administrators too.  Revoke write privileges for non-administrative users from the above programs and directories.''',
       'supporting_data': {
          'writable_progs': {
             'section': "description",
             'preamble': "The programs below can be modified by non-administrative users:",
          },
          'writable_dirs': {
             'section': "description",
             'preamble': "The directories below can be changed by non-administrative users:",
          },
       }
    },
    'WPC002': {
       'title': "Insecure Permissions on Files and Directories in Path (OBSELETE ISSUE)",
       'description': '''Some of the programs and directories in the %PATH% variable could be changed by non-administrative users.

This could allow certain users on the system to place malicious code into certain key directories, or to replace programs with malicious ones.  A malicious local user could use this technique to hijack the privileges of other local users, running commands with their privileges.
''',
       'recommendation': '''Programs run by multiple users should only be changable only by administrative users.  The directories containing these programs should only be changable only by administrators too.  Revoke write privileges for non-administrative users from the above programs and directories.''',
       'supporting_data': {
          'writable_progs': {
             'section': "description",
             'preamble': "The programs below are in the path of the user used to carry out this audit.  Each one can be changed by non-administrative users:",
          },
          'writable_dirs': {
             'section': "description",
             'preamble': "The directories below are in the path of the user used to carry out this audit.  Each one can be changed by non-administrative users:",
          }
       }
    },
    # TODO walk the whole registry looking for .exe and .dll in data?
    'WPC003': {
       'title': "Insecure Permissions In Windows Registry (TODO)",
       'description': '''Some registry keys that hold the names of programs run by other users were checked and found to have insecure permissions.  It would be possible for non-administrative users to modify the registry to cause different programs to be run.  This weakness could be abused by low-privileged users to run commands of their choosing with higher privileges.''',
       'recommendation': '''Modify the permissions on the above registry keys to allow only administrators write access.  Revoke write access from low-privileged users.''',
       'supporting_data': {
          'writable_reg_paths': {
             'section': "description",
             'preamble': "The registry keys below could be changed by non-administrative users:",
          },
       }
    },
    'WPC005': {
       'title': "Insecure Permissions On Windows Service Registry Keys (OBSELETED by WPC038 and others)",
       'description': '''Some registry keys that hold the names of programs that are run when Windows Services start were found to have weak file permissions.  They could be changed by non-administrative users to cause malicious programs to be run instead of the intended Windows Service Executable.''',
       'recommendation': '''Modify the permissions on the above programs to allow only administrators write access.  Revoke write access from low-privileged users.''',
       'supporting_data': {
          'writable_reg_paths': {
             'section': "description",
             'preamble': "The registry keys below could be changed by non-administrative users:",
          },
       }
    },
    'WPC007': {
       'title': "Write Permissions Allowed On Event Log File",
       'description': '''Some of the Event Log files could be changed by non-administrative users.  This may allow attackers to cover their tracks.''',
       'recommendation': '''Modify the permissions on the above files to allow only administrators write access.  Revoke write access from low-privileged users.''',
       'supporting_data': {
          'writable_eventlog_file': {
             'section': "description",
             'preamble': "The files below could be changed by non-administrative users:",
          },
       }
    },
    'WPC008': {
       'title': "Insecure Permissions On Event Log DLL",
       'description': '''Some DLL files used by Event Viewer to display logs could be changed by non-administrative users.  It may be possible to replace these with a view to having code run when an administrative user next views log files.''',
       'recommendation': '''Modify the permissions on the above DLLs to allow only administrators write access.  Revoke write access from low-privileged users.''',
       'supporting_data': {
          'writable_eventlog_dll': {
             'section': "description",
             'preamble': "The DLL files below could be changed by non-administrative users:",
          },
       }
    },
    'WPC009': {
       'title': "Insecure Permissions On Event Log Registry Key",
       'description': '''Some registry keys that hold the names of DLLs used by Event Viewer and the location of Log Files are writable by non-administrative users.  It may be possible to maliciouly alter the registry to change the location of log files or run malicious code.''',
       'recommendation': '''Modify the permissions on the above programs to allow only administrators write access.  Revoke write access from low-privileged users.''',
       'supporting_data': {
          'writable_eventlog_key': {
             'section': "description",
             'preamble': "The registry keys below could be changed by non-administrative users:",
          },
       }
    },
    'WPC010': {
       'title': "File Creation Allowed On Drive Root",
       'description': '''Some of the local drive roots allow non-administrative users to create files.  This could allow malicious files to be placed in on the server in the hope that they'll allow a local user to escalate privileges (e.g. create program.exe which might get accidentally launched by another user).''',
       'recommendation': '''Modify the permissions on the drive roots to only allow administrators write access.  Revoke write access from low-privileged users.''',
       'supporting_data': {
          'dir_add_file': {
             'section': "description",
             'preamble': "The following drives allow non-administrative users to write to their root directory:",
          },
       }
    },
    'WPC011': {
       'title': "Insecure (Non-NTFS) File System Used",
       'description': '''Some local drives use Non-NTFS file systems.  These drive therefore don't allow secure file permissions to be used.  Any local user can change any data on these drives.''',
       'recommendation': '''Use NTFS filesystems instead of FAT.  Ensure that strong file permissions are set - NTFS file permissions are insecure by default after FAT file systems are converted.''',
       'supporting_data': {
          'drive_and_fs_list': {
             'section': "description",
             'preamble': "The following drives use Non-NTFS file systems:",
          },
       }
    },
    'WPC012': {
       'title': "Insecure Permissions On Windows Services (OBSELETE)",
       'description': '''Some of the Windows Services installed have weak permissions.  This could allow non-administrators to manipulate services to their own advantage.  The impact depends on the permissions granted, but can include starting services, stopping service or even reconfiguring them to run a different program.  This can lead to denial of service or even privilege escalation if the service is running as a user with more privilege than a malicious local user.''',
       'recommendation': '''Review the permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'weak_service_perms': {
             'section': "description",
             'preamble': "Some Windows Services can be manipulated by non-administrator users:",
          },
       }
    },
    'WPC013': {
       'title': "Insecure Permissions On Files / Directories In System PATH",
       'description': '''Some programs/directories in the system path have weak permissions.  TODO which user are affected by this issue?''',
       'recommendation': '''Review the permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'writable_progs': {
             'section': "description",
             'preamble': "The following programs/DLLs in the system PATH can be manipulated by non-administrator users:",
          },
          'writable_dirs': {
             'section': "description",
             'preamble': "The following directories in the system PATH can be manipulated by non-administrator users:",
          },
       }
    },
    'WPC014': {
       'title': "Insecure Permissions On Files / Directories In Current User's PATH",
       'description': '''Some programs/directories in the path of the user used to perform this audit have weak permissions.''',
       'recommendation': '''Review the permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'writable_progs': {
             'section': "description",
             'preamble': "The following programs/DLLs in current user's PATH can be manipulated by non-administrator users:",
          },
          'writable_dirs': {
             'section': "description",
             'preamble': "The following directories in the current user's PATH can be manipulated by non-administrator users:",
          },
       }
    },
    'WPC015': {
       'title': "Insecure Permissions On Files / Directories In Users' PATHs (TODO)",
       'description': '''Some programs/directories in the paths of users on this system have weak permissions.''',
       'recommendation': '''Review the permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'writable_progs': {
             'section': "description",
             'preamble': "The following programs/DLLs in users' PATHs can be manipulated by non-administrator users:",
          },
          'writable_dirs': {
             'section': "description",
             'preamble': "The following directories in users' PATHs can be manipulated by non-administrator users:",
          },
       }
    },
    'WPC016': {
       'title': "Insecure Permissions On Running Programs (OBSELETED by WPC067)",
       'description': '''Some programs running at the time of the audit have weak file permissions.  The corresponding programs could be altered by non-administrator users.''',
       'recommendation': '''Review the permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'weak_perms_exes': {
             'section': "description",
             'preamble': "The following programs were running at the time of the audit, but could be changed on-disk by non-administrator users:",
          },
          'weak_perms_dlls': {
             'section': "description",
             'preamble': "The following DLLs are used by program which were running at the time of the audit.  These DLLs can be changed on-disk by non-administrator users:",
          },
       }
    },
    'WPC018': {
       'title': "Service Can Be Started By Non-Admin Users",
       'description': '''The service-level permissions on some Windows services allow them to be started by non-administrative users.  This can often be desirable, in which case this issue can be ignored.  However, sometimes it can allow users to expose or exploit a vulnerability connected with the service - e.g. it may listen on the network or it may have been tampered with by an attacker and they now need to start the service.  The permission is not always dangerous on its own, but can sometimes aid a local attacker.''',
       'recommendation': '''Review the service-level permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'principals_with_service_perm': {
             'section': "description",
             'preamble': "The SERVICE_START permission has been granted to the following non-administrative users:",
          },
       }
    },
    'WPC019': {
       'title': "Service Can Be Stopped By Non-Admin Users",
       'description': '''The service-level permissions on some Windows services allow them to be stopped by non-administrative users.  This can often be desirable, in which case this issue can be ignored.  However, sometimes it can allow users to evade monitoring services - e.g. Anti-virus.  This permission can also be required in order to exploit other weaknesses such as weak file permissions on service executables.  The permission is not always dangerous on its own, but can sometimes aid a local attacker.''',
       'recommendation': '''Review the service-level permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'principals_with_service_perm': {
             'section': "description",
             'preamble': "The SERVICE_STOP permission has been granted to the following non-administrative users:",
          },
       }
    },
    'WPC020': {
       'title': "Service Can Be Paused/Resumed By Non-Admin Users",
       'description': '''The service-level permissions on some Windows services allow them to be paused/resumed by non-administrative users.  This can often be desirable, in which case this issue can be ignored.  However, sometimes it can allow users to allow users to evade monitoring - e.g. from Anti-virus services.  The permission is not always dangerous on its own, but can sometimes aid a local attacker.''',
       'recommendation': '''Review the service-level permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'principals_with_service_perm': {
             'section': "description",
             'preamble': "The SERVICE_PAUSE_CONTINUE permission has been granted to the following non-administrative users:",
          },
       }
    },
    'WPC021': {
       'title': "Service Can Be Reconfigured By Non-Admin Users",
       'description': '''The service-level permissions on some Windows services allow them to be reconfigured by non-administrative users.  This should not normally be required and is inherently insecure.  It could certain users alter the program which is run when this service start and to alter which user the service runs as.  The most likely attack would be to reconfigure the service to run as LocalSystem with no password and to select a malicious executable.  This would give the attacker administrator level access to the local system.''',
       'recommendation': '''Review the service-level permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'principals_with_service_perm': {
             'section': "description",
             'preamble': "The SERVICE_CHANGE_CONFIG permission has been granted to the following non-administrative users:",
          },
       }
    },
    'WPC022': {
       'title': "Service Can Be Deleted By Non-Admin Users",
       'description': '''The service-level permissions on some Windows services allow them to be deleted by non-administrative users.  This should not normally be required and is inherently insecure.  It could allow local users to delete the service.  This may allow them to evade monitor - e.g. from Anti-virus - or to disrupt normal business operations.  Note that the user would not be able to replace the service as administrator level rights are required to create new services.''',
       'recommendation': '''Review the service-level permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'principals_with_service_perm': {
             'section': "description",
             'preamble': "The DELETE permission has been granted to the following non-administrative users:",
          },
       }
    },
    'WPC023': {
       'title': "Service Permissions Can Be Altered By Non-Admin Users",
       'description': '''The service-level permissions on some Windows services allow some non-administrative users to set any service-level permissions of their choosing.  This should not normally be required and is inherently insecure.  It has a similar effect to granting the user DELETE and SERVICE_CHANGE_CONFIG.  These powerful rights could allow the user to reconfigure a service to provide them with administrator level access, or simply to delete the service, disrupting normal business operations.''',
       'recommendation': '''Review the service-level permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'principals_with_service_perm': {
             'section': "description",
             'preamble': "The WRITE_DAC permission has been granted to the following non-administrative users:",
          },
       }
    },
    'WPC024': {
       'title': "Non-Admin Users Can Take Ownership of Service",
       'description': '''The service-level permissions on some Windows services allow ownership to be claimed by some non-administrative users.  This should not normally be required and is inherently insecure.  It has a similar effect to granting the user WRITE_DAC (and thus DELETE and SERVICE_CHANGE_CONFIG).  These powerful rights could allow the user to reconfigure a service to provide them with administrator level access, or simply to delete the service, disrupting normal business operations.''',
       'recommendation': '''Review the service-level permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'principals_with_service_perm': {
             'section': "description",
             'preamble': "The WRITE_OWNER permission has been granted to the following non-administrative users:",
          },
       }
    },
    'WPC025': {
       'title': "Services Owned By Non-Admin Users",
       'description': '''The owner in the security descriptor for some services is set to a non-administrative user.  This should not normally be required and is inherently insecure.  It has a similar effect to granting the user WRITE_DAC (and thus DELETE and SERVICE_CHANGE_CONFIG).  These powerful rights could allow the user to reconfigure a service to provide them with administrator level access, or simply to delete the service, disrupting normal business operations.''',
       'recommendation': '''Review the service-level permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'principals_with_service_ownership': {
             'section': "description",
             'preamble': "The following services are owned by non-administrative users:",
          },
       }
    },
    'WPC026': {
       'title': "Delete Permission Granted On Windows Service Executables",
       'description': '''Some of the programs that are run when Windows Services start were found to have weak file permissions.  It is possible for non-administrative local users to delete some of the Windows Service executables with malicious programs.  This could lead to disruption or denial of service.''',
       'recommendation': '''Modify the permissions on the above programs to allow only administrators delete permission.  Revoke delete permission from low-privileged users.''',
       'supporting_data': {
          'service_exe_write_perms': {
             'section': "description",
             'preamble': "The programs below have DELETE permission granted to non-administrative users:",
          },
       }
    },
    'WPC027': {
       'title': "Append Permission Granted Windows Service Executables",
       'description': '''Some of the programs that are run when Windows Services start were found to have weak file permissions.  It is possible for non-administrative local users to append to some of the Windows Service executables with malicious programs.  This is unlikely to be exploitable for .exe files, but is it bad security practise to allow more access than necessary to low-privileged users.''',
       'recommendation': '''Modify the permissions on the above programs to allow only administrators delete permission.  Revoke delete permission from low-privileged users.''',
       'supporting_data': {
          'service_exe_write_perms': {
             'section': "description",
             'preamble': "The programs below have FILE_APPEND permission granted to non-administrative users:",
          },
       }
    },
    'WPC028': {
       'title': "Untrusted Users Can Modify Windows Service Executables",
       'description': '''Some of the programs that are run when Windows Services start were found to have weak file permissions.  It is possible for non-administrative local users to replace some of the Windows Service executables with malicious programs.  This could be abused to execute programs with the privileges of the Windows services concerned.''',
       'recommendation': '''Modify the permissions on the above programs to allow only administrators write access.  Revoke write access from low-privileged users.''',
       'supporting_data': {
          'service_exe_write_perms': {
             'section': "description",
             'preamble': "The programs below have FILE_WRITE, WRITE_DAC or WRITE_OWNER permission granted to non-administrative users:",
          },
       }
    },
    'WPC029': {
       'title': "Windows Service Executables Owned By Untrusted Users",
       'description': '''Some of the programs that are run when Windows Services start were found to be owned by untrusted users.  Consequently, these programs can be replace with malicious programs by low-privileged users.  This could result is users stealing the privileges of the services affected.''',
       'recommendation': '''Change the ownership of the affected programs.  They should be owned by administrators.''',
       'supporting_data': {
          'service_exe_owner': {
             'section': "description",
             'preamble': "The programs below were owned by non-administrative users:",
          },
       }
    },
    'WPC030': {
       'title': "Parent Directories of Windows Service Executables Allow Untrusted Users FILE_DELETE_CHILD and FILE_ADD_SUBDIR Permissions",
       'description': '''Some of the programs that are run when Windows Services start were found to have parent directories that had both FILE_DELETE_CHILD and FILE_ADD_SUBDIR permissions granted to untrusted users.  This combination of directory permissions allows entire portions of the parent directory structure can be deleted and replaced, allowing the service executable to be susbstituted with a malicoius one.  In this way low-privileged users could steal the privileges of the services affected.''',
       'recommendation': '''Change the directory permissions granted to low-privileged users.  They should never be granted FILE_DELETE_CHILD permission to the parent directory of a program.  FILE_ADD_SUBDIR should be used sparingly.''',
       'supporting_data': {
          'service_exe_parent_dir_perms': {
             'section': "description",
             'preamble': "The programs had parent directories which granted non-administrative users FILE_DELETE_CHILD and FILE_ADD_SUBDIR permissions:",
          },
       }
    },
    'WPC031': {
       'title': "Parent Directories of Windows Service Executables Allow Untrusted Users DELETE Permissions And Can Be Replaced Because of FILE_ADD_SUBDIR Permission",
       'description': '''Some of the programs that are run when Windows Services start were found to have parent directories that had DELETE permission granted to untrusted users. Further the parent directories of the directories affected had FILE_ADD_SUBDIR granted for low-privileged users.  This combination of directory permissions allows entire portions of the parent directory structure can be deleted and replaced, allowing the service executable to be susbstituted with a malicoius one.  In this way low-privileged users could steal the privileges of the services affected.''',
       'recommendation': '''Change the directory permissions granted to low-privileged users.  They should never be granted DELETE permission to the parent directory of a program.  FILE_ADD_SUBDIR should be used sparingly.''',
       'supporting_data': {
          'service_exe_parent_grandparent_write_perms': {
             'section': "description",
             'preamble': "The programs below were owned by non-administrative users:",
          },
       }
    },
    'WPC032': {
       'title': "Parent Directories of Windows Service Executables Can Have File Permissions Altered By Untrusted Users",
       'description': '''Some of the programs that are run when Windows Services start were found to have parent directories that had the permissions WRITE_OWNER or WRITE_DAC granted to untrusted users.  Consequently, low-privileged users could grant themselves any privilege they desired on these directories.  This could result in entire portions of the parent directory structure can be deleted and replaced, allowing the service executable to be susbstituted with a malicoius one.  In this way low-privileged users could steal the privileges of the services affected.''',
       'recommendation': '''Change the directory permissions granted to low-privileged users.  Service executables should never have WRITE_OWNER or WRITE_DAC granted to low privileged users.''',
       'supporting_data': {
          'service_exe_parent_dir_perms': {
             'section': "description",
             'preamble': "The directories below had the permissions WRITE_OWNER or WRITE_DAC granted to non-administrative users:",
          },
       }
    },
    'WPC033': {
       'title': "Parent Directories of Windows Service Executables Owned By Untrusted Users",
       'description': '''Some of the programs that are run when Windows Services start were found to have parent directories that were owned by untrusted users.  Consequently, entire portions of the parent directory structure can be deleted and replaced, allowing the service executable to be susbstituted with a malicoius one.  This could result is users stealing the privileges of the services affected.''',
       'recommendation': '''Change the ownership of the affected directories.  They should be owned by administrators.''',
       'supporting_data': {
          'service_exe_parent_dir_untrusted_ownership': {
             'section': "description",
             'preamble': "The directories below were owned by non-administrative users:",
          },
       }
    },
    'WPC034': {
       'title': "Windows Service Executables Allow DELETE Permissions To Untrusted Users And Can Be Replaced Because of FILE_ADD_FILE Permission On Parent Directory",
       'description': '''Some of the programs that are run when Windows Services start were found to have DELETE permission granted to low-privileged users.  Furthermore, the parent directory allowed FILE_ADD_FILE permission to low-privileged users.  This combination of directory permissions allows the service executable to be deleted and replaced malicoius program.  In this way low-privileged users could steal the privileges of the services affected.''',
       'recommendation': '''Change the file and directory permissions granted to low-privileged users.  They should never be granted DELETE permission on a service executable.  The use of FILE_ADD_FILE on parent directories should also be avoided.''',
       'supporting_data': {
          'service_exe_file_parent_write_perms': {
             'section': "description",
             'preamble': "The programs had parent directories which granted non-administrative users FILE_DELETE_CHILD and FILE_ADD_SUBDIR permissions:",
          },
       }
    },
    'WPC035': {
       'title': "Windows Service Registry Keys Are Owned By Untrusted Users",
       'description': '''Configuration information for Windows Service is stored in the registry.  Some of the keys were found to be owned by non-administrative users.  It would be possible for these users to maliciously modify the registry to change the executable run to a malicious one, or to make the service run with higher privileges.  It could lead to a low-privileged user escalating privilges to local administrator.''',
       'recommendation': '''Change the ownership of registry keys pertaining to Windows Servies.  Keys should only be owned by administors only.''',
       'supporting_data': {
          'service_exe_regkey_untrusted_ownership': {
             'section': "description",
             'preamble': "The registry keys below were owned by non-administrative users:",
          },
       }
    },
    'WPC036': {
       'title': "Permissions on Windows Service Registry Keys Can be Changed By Untrusted Users",
       'description': '''Configuration information for Windows Service is stored in the registry.  Some of the keys were found to have WRITE_DAC or WRITE_OWNER permissions granted for non-administrative users.  After modifying the permission as desired, it would be possible for these users to maliciously modify the registry to change the executable run to a malicious one, or to make the service run with higher privileges.  It could lead to a low-privileged user escalating privilges to local administrator.''',
       'recommendation': '''Change the permissions of registry keys pertaining to Windows Servies.  Keys should never allow WRITE_DAC or WRITE_OWNER for low-privileged users.''',
       'supporting_data': {
          'service_reg_perms': {
             'section': "description",
             'preamble': "The registry keys below had WRITE_DAC or WRITE_OWNER granted for non-administrative users:",
          },
       }
    },
    'WPC037': {
       'title': "Windows Service Registry Values Can be Changed By Untrusted Users",
       'description': '''Configuration information for Windows Service is stored in the registry.  Some of the keys were found to have the KEY_SET_VALUE permission granted for non-administrative users.  It would be possible for these users to maliciously modify the registry to change the executable run to a malicious one, or to make the service run with higher privileges.  It could lead to a low-privileged user escalating privilges to local administrator.''',
       'recommendation': '''Change the permissions of registry keys pertaining to Windows Servies.  Service registry keys should never allow KEY_SET_VALUE for low-privileged users.''',
       'supporting_data': {
          'service_reg_perms': {
             'section': "description",
             'preamble': "The registry keys below had KEY_SET_VALUE granted for non-administrative users:",
          },
       }
    },
    'WPC038': {
       'title': "Windows Service Registry Keys Allow KEY_CREATE_LINK",
       'description': '''Configuration information for Windows Service is stored in the registry.  Some of the keys were found to have the KEY_CREATE_LINK permission granted for non-administrative users.  This allows low-privileged users to create Registry Symbolic Links.  While this feature appears to be poorly documented by Microsoft, there is sample code freely available on the Internet.  The impact of this issue is similar to that for the KEY_CREATE_SUB_KEY issue: It may be possible for low privileged users to manipulate services - though this would depend on how the service responded to the addition of new registry keys.''',
       'recommendation': '''Change the permissions of registry keys pertaining to Windows Servies.  Service registry keys should never allow KEY_CREATE_LINK for low-privileged users.''',
       'supporting_data': {
          'service_reg_perms': {
             'section': "description",
             'preamble': "The registry keys below had KEY_CREATE_LINK granted for non-administrative users:",
          },
       }
    },
    'WPC039': {
       'title': "Windows Service Registry Keys Allow Untrusted Users To Create Subkeys",
       'description': '''Configuration information for Windows Service is stored in the registry.  Some of the keys were found to have the KEY_CREATE_SUB_KEY permission granted for non-administrative users.  It may be possible for low privileged users to manipulate service - though this would depend on how the service responded to the addition of new registry keys.''',
       'recommendation': '''Review the permissions of keys with KEY_CREATE_SUB_KEY granged.  Revoke KEY_CREATE_SUB_KEY permissions for non-administrative users where possible.''',
       'supporting_data': {
          'service_reg_perms': {
             'section': "description",
             'preamble': "The registry keys below had KEY_CREATE_SUB_KEY granted for non-administrative users:",
          },
       }
    },
    'WPC040': {
       'title': "Windows Service Registry Keys Allow Untrusted Users To Delete Them",
       'description': '''Configuration information for Windows Service is stored in the registry.  Some of the keys were found to have the DELETE permission granted for non-administrative users.  Low privileged users could delete the service configuration information, disrupting normal business operations.''',
       'recommendation': '''Change the permissions of registry keys pertaining to Windows Servies.  Service registry keys should never allow DELETE for low-privileged users.''',
       'supporting_data': {
          'service_reg_perms': {
             'section': "description",
             'preamble': "The registry keys below had DELETE granted for non-administrative users:",
          },
       }
    },
    'WPC041': {
       'title': "Windows Service Registry Keys Have Parent Keys Owned By Untrusted Users",
       'description': '''Configuration information for Windows Service is stored in the registry.  Some of the parent keys were found to be owned by non-administrative users.  This could allow low-privileged users to alter the permissions on the keys concerned, delete them, add subkeys and add/alter registry values for that key.  This probably constitutes a denial of service risk, but may also allow privilege escalation depending on how the service responds to registry keys being tampered with.''',
       'recommendation': '''Change the ownership of registry keys pertaining to Windows Servies.  Service registry keys should be owned by the administrators group.''',
       'supporting_data': {
          'service_regkey_parent_untrusted_ownership': {
             'section': "description",
             'preamble': "The registry keys below were owned by non-administrative users:",
          },
       }
    },
    'WPC042': {
       'title': "Permissions on Windows Service Registry Keys Can Be Changed By Untrusted Users",
       'description': '''Configuration information for Windows Service is stored in the registry.  TODO.''',
       'recommendation': '''TODO.''',
       'supporting_data': {
          'service_regkey_parent_perms': {
             'section': "description",
             'preamble': "The registry keys below were owned by non-administrative users:",
          },
       }
    },
    'WPC043': {
       'title': "Windows Service Registry Keys Can Be Deleted And Replaced By Untrusted Users",
       'description': '''Configuration information for Windows Service is stored in the registry.  TODO.''',
       'recommendation': '''TODO.''',
       'supporting_data': {
          'service_regkey_parent_grandparent_write_perms': {
             'section': "description",
             'preamble': "The registry keys below were owned by non-administrative users:",
          },
       }
    },
    'WPC046': {
       'title': "Windows Registry Keys Containing Program Owned By Untrusted Users",
       'description': '''Some of the registry keys holding the names of programs run by other users could be changed by non-administrative users.  TODO''',
       'recommendation': '''TODO''',
       'supporting_data': {
          'regkey_untrusted_ownership': {
             'section': "description",
             'preamble': "The registry keys below can be changed by non-administrative users:",
          },
       }
    },
    'WPC047': {
       'title': "Windows Registry Keys Containing Programs Can Have Permissions Changed By Untrusted Users",
       'description': '''Some of the registry keys holding the names of programs run by other users could be changed by non-administrative users.  TODO''',
       'recommendation': '''TODO''',
       'supporting_data': {
          'regkey_perms': {
             'section': "description",
             'preamble': "The registry keys below can be changed by non-administrative users:",
          },
       }
    },
    'WPC048': {
       'title': "Windows Registry Keys Containing Program Names Can Be Changed By Untrusted Users",
       'description': '''Some of the registry keys holding the names of programs run by other users could be changed by non-administrative users.  It would be possible for an attacker to substitute the name of malicious program which then stole the privileges of other accounts.''',
       'recommendation': '''The keys below should only have write access for administrators.''',
       'supporting_data': {
          'regkey_perms': {
             'section': "description",
             'preamble': "The registry keys below can be changed by non-administrative users:",
          },
       }
    },
    'WPC049': {
       'title': "Windows Registry Keys Containing Programs Can Have Subkey Added By Untrusted Users",
       'description': '''Some of the registry keys holding the names of programs run by other users could be changed by non-administrative users.  TODO''',
       'recommendation': '''TODO''',
       'supporting_data': {
          'regkey_perms': {
             'section': "description",
             'preamble': "The registry keys below can be changed by non-administrative users:",
          },
       }
    },
    'WPC050': {
       'title': "Windows Registry Keys Containing Programs Can Be Deleted",
       'description': '''Some of the registry keys holding the names of programs run by other users could be changed by non-administrative users.  TODO''',
       'recommendation': '''TODO''',
       'supporting_data': {
          'regkey_perms': {
             'section': "description",
             'preamble': "The registry keys below can be changed by non-administrative users:",
          },
       }
    },
    'WPC051': {
       'title': "Windows Service Has Insecurely Quoted Path",
       'description': '''The path to the executable for the service contains one or more spaces and quotes have not been correctly used around the path.  The path is therefore ambiguous which could result in the wrong program being executed when the service is started - e.g. "C:\\program.exe" instead of "C:\\program files\\foo\\bar.exe".  The issue is not necessarily exploitable unless a local attacker has permissions to add an alternative executable to the correct location on the filesystem.  The impact of the issue should be considered higher for services that run with high privileges.''',
       'recommendation': '''Use quotes around the path to executables if they contain spaces: C:\\program files\\foo\\bar.exe -> "C:\\program files\\foo\\bar.exe".''',
       'supporting_data': {
          'service_info': {
             'section': "description",
             'preamble': "The following services have insecurely quoted paths:",
          },
       }
    },
    'WPC052': {
       'title': "Windows Service DLL Can Be Replaced",
       'description': '''Each windows service has a corresponding registry key in HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services.  Some services have a "Parameters" subkey and a value called "ServiceDll" (e.g. HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\someservice\\Parameters\\ServiceDll = c:\\dir\\foo.dll").  The DLL for some of the services on the system audited can be replaced by non-administrative users.  TODO how and by whom?  Users able to replace the service DLL could run code of their choosing with the privileges of the service.''',
       'recommendation': '''Set strong file permissions on the service DLLs and their partent directories.''',
       'supporting_data': {
          'service_dll': {
             'section': "description",
             'preamble': "The following services have weak file permissions on the service DLLs:",
          },
       }
    },
    'WPC053': {
       'title': "Context Handler Menus Use Poorly Protected Files",
       'description': '''Context Menus appear in Windows Explorer when files are right-clicked.  Each has a corresponding DLL or .EXE.  Some of the referenced DLLs or .EXE file can be replaced by non-administrative users.  As these context menus are used by all system users, there is a possibility that a user might run malicious code of an attacker's choosing if the DLLs or .EXEs are modified.  TODO how can the files be modified?

Context Menu Handlers are described here: http://msdn.microsoft.com/en-us/library/windows/desktop/cc144171(v=vs.85).aspx

Shell Extenstion Handlers more generally are described here: http://msdn.microsoft.com/en-us/library/windows/desktop/cc144067(v=vs.85).aspx       ''',
       'recommendation': '''Set strong file permissions on the service DLLs and their partent directories.''',
       'supporting_data': {
          'regkey_ref_replacable_file': {
             'section': "description",
             'preamble': "The following shell extension use DLLs or .EXE files with weak file permissions:",
          },
       }
    },
    'WPC054': {
       'title': "Property Sheet Handlers Use Poorly Protected Files",
       'description': '''"Property Sheets" appear in Windows Explorer when files are right-clicked and the "Properties" context menu selected.  The DLLs or .EXEs used to generate these property sheets can be replaced by non-administrative users.  As these property sheets are used by all system users, there is a possibility that a user might run malicious code of an attacker's choosing if the DLLs or .EXEs are modified.  TODO how can the files be modified?  

Property Sheet Handlers are described here: http://msdn.microsoft.com/en-us/library/windows/desktop/cc144106(v=vs.85).aspx

Shell Extenstion Handlers more generally are described here: http://msdn.microsoft.com/en-us/library/windows/desktop/cc144067(v=vs.85).aspx       ''',
       'recommendation': '''Set strong file permissions on the service DLLs and their partent directories.''',
       'supporting_data': {
          'regkey_ref_replacable_file': {
             'section': "description",
             'preamble': "The following shell extension use DLLs or .EXE files with weak file permissions:",
          },
       }
    },
    'WPC055': {
       'title': "Copy Hook Handlers Use Poorly Protected Files",
       'description': '''"Copy Hook Handlers" are a type of Windows Explorer shell extension that can control the copying, moving, deleting and renaming of files and folder.  Each as a corresponding DLL or .EXE.  Some of DLLs or .EXEs used can be replaced by non-administrative users.  As Copy Hooks are used by all system users, there is a possibility that a user might run malicious code of an attacker's choosing if the DLLs or .EXEs are modified.  TODO how can the files be modified?

Copy Hook Handlers are described here: http://msdn.microsoft.com/en-us/library/windows/desktop/cc144063(v=vs.85).aspx

Shell Extenstion Handlers more generally are described here: http://msdn.microsoft.com/en-us/library/windows/desktop/cc144067(v=vs.85).aspx       ''',
       'recommendation': '''Set strong file permissions on the service DLLs and their partent directories.''',
       'supporting_data': {
          'regkey_ref_replacable_file': {
             'section': "description",
             'preamble': "The following shell extension use DLLs or .EXE files with weak file permissions:",
          },
       }
    },
    'WPC056': {
       'title': "DragDrop Handlers Use Poorly Protected Files",
       'description': '''"DragDrop Handlers" are a type of Windows Explorer shell extension that determine behaviour when files or folders are dragged and dropped.  Each as a corresponding DLL or .EXE.  Some of DLLs or .EXEs used can be replaced by non-administrative users.  As DragDrop Handlers are used by all system users, there is a possibility that a user might run malicious code of an attacker's choosing if the DLLs or .EXEs are modified.  TODO how can the files be modified?

DragDrop Handlers are described here: http://msdn.microsoft.com/en-us/library/windows/desktop/cc144171(v=vs.85).aspx

Shell Extenstion Handlers more generally are described here: http://msdn.microsoft.com/en-us/library/windows/desktop/cc144067(v=vs.85).aspx       ''',
       'recommendation': '''Set strong file permissions on the service DLLs and their partent directories.''',
       'supporting_data': {
          'regkey_ref_replacable_file': {
             'section': "description",
             'preamble': "The following shell extension use DLLs or .EXE files with weak file permissions:",
          },
       }
    },
    'WPC057': {
       'title': "Column Handlers Use Poorly Protected Files",
       'description': '''"Column Handlers" are a type of Windows Explorer shell extension that determine behaviour the users tries to add or remove columns from the display.  Each as a corresponding DLL or .EXE.  Some of DLLs or .EXEs used can be replaced by non-administrative users.  As Column Handlers are used by all system users, there is a possibility that a user might run malicious code of an attacker's choosing if the DLLs or .EXEs are modified.  TODO how can the files be modified?

Column Handlers are described here: http://msdn.microsoft.com/en-us/library/windows/desktop/bb776831(v=vs.85).aspx

Shell Extenstion Handlers more generally are described here: http://msdn.microsoft.com/en-us/library/windows/desktop/cc144067(v=vs.85).aspx       ''',
       'recommendation': '''Set strong file permissions on the service DLLs and their partent directories.''',
       'supporting_data': {
          'regkey_ref_replacable_file': {
             'section': "description",
             'preamble': "The following shell extension use DLLs or .EXE files with weak file permissions:",
          },
       }
    },
    # TODO checks for these:
    # Icon Overlay Handlers http://msdn.microsoft.com/en-us/library/windows/desktop/cc144123(v=vs.85).aspx
    # Search Handlers http://msdn.microsoft.com/en-us/library/windows/desktop/bb776834(v=vs.85).aspx

    # TODO add RunOnceEx keys to this issue + HKCU\run, runonce, runonceex
    'WPC058': {
       'title': "Registry \"Run\" Keys Reference Programs With Weak Permissions",
       'description': '''The Run and RunOnce keys under HKLM reference programs that are run when a user logs in with the privielges of that user.  Some of the programs referenced by the registry keys can be modified by non-administrative user.  This could allow a malcious user to run code of their choosing under the context of other user accounts.  Run and RunOnce are described here: http://msdn.microsoft.com/en-us/library/aa376977(v=vs.85).aspx''',
       'recommendation': '''Set strong file permissions on the executables their parent directories.''',
       'supporting_data': {
          'regkey_ref_file': {
             'section': "description",
             'preamble': "The programs referenced from the registry can be modified by non-admin users:",
          },
       }
    },
    'WPC059': {
       'title': "Registry \"RunServices\" Keys Reference Programs With Weak Permissions",
       'description': '''The RunServices and RunServicesOnce keys under HKLM reference programs that are run before the Login Dialog box appears.  Commands are run as SYSTEM.  Some of the programs referenced by the registry keys can be modified by non-administrative user.  This could allow a malcious user to run code of their choosing under the context of the SYSTEM account.  RunServices and RunServicesOnce are described here: http://support.microsoft.com/kb/179365''',
       'recommendation': '''Set strong file permissions on the executables their parent directories.''',
       'supporting_data': {
          'regkey_ref_file': {
             'section': "description",
             'preamble': "The programs referenced from the registry can be modified by non-admin users:",
          },
       }
    },
    'WPC060': {
       'title': "KnownDLLs Have Weak Permissions",
       'description': '''The KnownDLLs registry key holds the name and path of various DLLs.  Programs that rely on these DLLs will load them from the known location instead of searching the rest of the PATH.  More information on KnownDLLs can be found here: http://support.microsoft.com/kb/164501''',
       'recommendation': '''Set strong file permissions on the DLLs their parent directories.''',
       'supporting_data': {
          'regkey_ref_file': {
             'section': "description",
             'preamble': "The programs referenced from the registry can be modified by non-admin users:",
          },
       }
    },
    'WPC061': {
       'title': "CLSID References DLLs/EXEs With Weak File Permissions (experimental)",
       'description': '''Some of the CLSIDs reference files with insecure permissions.  This may indicate the presence of a vulnerability, but it depends what the CLSID is used for.  Try searching the registry for the CLSIDs below to determine how they are used and if this issue might be exploitable.

Further information about CLSIDs is available here: http://msdn.microsoft.com/en-us/library/windows/desktop/ms691424(v=vs.85).aspx''',
       'recommendation': '''Set strong file permissions on files referenced from CLSIDs.''',
       'supporting_data': {
          'regkey_ref_file': {
             'section': "description",
             'preamble': "The programs referenced from the registry can be modified by non-admin users:",
          },
       }
    },
    'WPC062': {
       'title': "Windows Service Executable Is Missing",
       'description': '''Each Windows Service has a corresponding executable.  The executables for some services were missing at the time of the audit.  This can sometimes be caused programs being manually deleted instead of being properly uninstalled.  Although this configuration is unusual and probably undesirable, it is unlikely to be a security issue unless an attacker can recreate the executables in question - an issue that was NOT checked for (please check manually).  It may be an indication that an attacker has previously abused a Windows service and left it in a half-configured state, so investigating the cause of the problem is advised.''',
       'recommendation': '''Investigate why the service is broken and either fix or remove the service as appropriate.''',
       'supporting_data': {
          'service_no_exe': {
             'section': "description",
             'preamble': "The following Windows Services has missing executables:",
          },
       }
    },
    'WPC063': {
       'title': "Windows Service Running Under Domain Account",
       'description': '''The configuration for each Windows Service specifies the user context under which the service runs.  Often services run as Built-in security pricipals such as LocalSystem, Network Service, Local Service, etc. or as a dedicated local user account.  In the case of the system audited, some of the Windows Services were found to run in the context of a Domain account.  It would therefore be possible for any attacker who gained local admin rights on the system to recover the cleartext password for the Domain accounts in question.  Depending on the priviliges of those accounts, it may be possible for an attacker to abuse the accounts to compromise further systems on the network.''',
       'recommendation': '''Ensure that Domain accounts are only used when absolutely necessary.  When they are used, ensure that the group memberships of the account are restricted to only those required - avoiding membership of Domain Admins.  Where possible also ensure that service accounts are only able to logon from a whitelist of named workstations.  These recommendations help to limit the potential abuse of domain accounts.''',
       'supporting_data': {
          'service_domain_user': {
             'section': "description",
             'preamble': "The following windows services run in the context of Domain accounts:",
          },
       }
    },
    'WPC064': {
       'title': "Windows Service Running Under Named Local Account",
       'description': '''The configuration for each Windows Service specifies the user context under which the service runs.  Often services run as Built-in security pricipals such as LocalSystem, Network Service, Local Service, etc.  In the case of the system audited, some of the Windows Services were found to run in the context of a local account that wasn't a Built-in security principal.  This can be a secure configuration and indeed is recommended configuration for some services such as SQL Server.  However, if administrators have similar services running on other systems, they sometimes configure the Windows Service account to have the same password on each.  It would therefore be possible for any attacker who gained local admin rights on the system to recover the cleartext password for the local Windows Service accounts in question.  It passwords are reused, it may be possible for an attacker to abuse the accounts to compromise further systems on the network.''',
       'recommendation': '''Ensure that the group memberships of the account are restricted to only those required - avoiding membership of the Administrators group.  Where possible also ensure that service accounts are not able to log on interactively, as batch jobs or log in over the network.  These recommendations help to limit the potential abuse of windows service accounts.''',
       'supporting_data': {
          'service_domain_user': {
             'section': "description",
             'preamble': "The following windows services run in the context of local accounts:",
          },
       }
    },
    'WPC065': {
       'title': "Windows Services for Pentesting/Auditing Tools Found",
       'description': '''Some of the Windows service running appear to correspond to tools that are commons used for pentesting or auditing.  These may or may not present a security problem.  The main purpose of this issue is to advise the auditor to check if they accidentally added any Windows services.''',
       'recommendation': '''Check each of the Windows services below and remove them if they have been added during the pentest/audit.''',
       'supporting_data': {
          'sectool_services': {
             'section': "description",
             'preamble': "The following windows services appear to be pentesting/auditing tools:",
          },
       }
    },
    'WPC066': {
       'title': "Files for Pentesting/Auditing Tools Found (TODO)",
       'description': '''Some of the files found during the audit have the same name as tools used during pentesting and security auditing.  These may or may not present a security problem.  The main purpose of this issue is to advise the auditor to check if they forgot to remove any tools.''',
       'recommendation': '''Check each of the files below and remove them if they have been added during the pentest/audit.''',
       'supporting_data': {
          'sectool_files': {
             'section': "description",
             'preamble': "The following files appear to be pentesting/auditing tools:",
          },
       }
    },
    'WPC067': {
       'title': "Executables for Running Processes Can Be Modified On Disk",
       'description': '''The file permissions for the processes running at the time of the audit were checked.  The executables for some of the processes could be replaced by non-administrative users.  This could enable an attacker to escalate privilege to the owner of the processes concerned.  An attacker would need to replace the program on disk and wait for the program to be run again as the user concerned.''',
       'recommendation': '''Set strong file permissions on each of the programs below.  Also set strong file permissions on parent directories.  Ideally only administrative users would have the ability to change programs run by multiple users.  Note that this issue can usually be considered a false positive is users are simply running programs from their home directory - provided that no other non-admin users can modify them.''',
       'supporting_data': {
          'process_exe': {
             'section': "description",
             'preamble': "The following files could be replaced by non-administrative users (TODO: how?):",
          },
       }
    },
    'WPC068': {
       'title': "DLLs Used by Running Processes Can Be Modified On Disk",
       'description': '''The file permissions for DLLs used by processes running at the time of the audit were checked.  The DLLs for some of the processes could be replaced by non-administrative users.  This could enable an attacker to escalate privilege to the owner of the processes concerned.  An attacker would need to replace the DLL on disk and wait for the program to be run again as the user concerned.''',
       'recommendation': '''Set strong file permissions on each of the DLLs below.  Also set strong file permissions on parent directories.  Ideally only administrative users would have the ability to change DLLs used by multiple users.    Note that this issue can usually be considered a false positive is users are simply running programs from their home directory - provided that no other non-admin users can modify them.''',
       'supporting_data': {
          'process_dll': {
             'section': "description",
             'preamble': "The following files could be replaced by non-administrative users (TODO: how?):",
          },
       }
    },
    'WPC069': {
       'title': "Processes Security Descriptor Allow Access To Non-Admin Users (TODO)",
       'description': '''TODO.  Writeme+Fixme.  This issue currently get false positives about non-priv users being able to change their own process.  Also needs to take account of RESTRICTED processes http://blogs.msdn.com/b/aaron_margosis/archive/2004/09/10/227727.aspx http://msdn.microsoft.com/en-us/library/ms972827.aspx''',
       'recommendation': '''TODO''',
       'supporting_data': {
          'process_perms': {
             'section': "description",
             'preamble': "TODO",
          },
       }
    },
    'WPC070': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeAssignPrimaryTokenPrivilege",
       'description': '''TODO SE_ASSIGNPRIMARYTOKEN_NAME TEXT("SeAssignPrimaryTokenPrivilege") Required to assign the primary token of a process.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Replace a process-level token'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC071': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeBackupPrivilege",
       'description': '''TODO SE_BACKUP_NAME TEXT("SeBackupPrivilege") Required to perform backup operations. This privilege causes the system to grant all read access control to any file, regardless of the access control list (ACL) specified for the file. Any access request other than read is still evaluated with the ACL. This privilege is required by the RegSaveKey and RegSaveKeyExfunctions. The following access rights are granted if this privilege is held: READ_CONTROL ACCESS_SYSTEM_SECURITY FILE_GENERIC_READ FILE_TRAVERSE''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Back up files and directories'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC072': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeCreatePagefilePrivilege",
       'description': '''TODO SE_CREATE_PAGEFILE_NAME TEXT("SeCreatePagefilePrivilege") Required to create a paging file. .''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Create a pagefile'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC073': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeCreateTokenPrivilege",
       'description': '''TODO SE_CREATE_TOKEN_NAME TEXT("SeCreateTokenPrivilege") Required to create a primary token.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Create a token object'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC074': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeDebugPrivilege",
       'description': '''TODO SE_DEBUG_NAME TEXT("SeDebugPrivilege") Required to debug and adjust the memory of a process owned by another account.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Debug programs'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC075': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeEnableDelegationPrivilege",
       'description': '''TODO SE_ENABLE_DELEGATION_NAME TEXT("SeEnableDelegationPrivilege") Required to mark user and computer accounts as trusted for delegation.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Enable computer and user accounts to be trusted for delegation'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC076': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeLoadDriverPrivilege",
       'description': '''TODO SE_LOAD_DRIVER_NAME TEXT("SeLoadDriverPrivilege") Required to load or unload a device driver.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Load and unload device drivers'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC077': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeMachineAccountPrivilege",
       'description': '''TODO SE_MACHINE_ACCOUNT_NAME TEXT("SeMachineAccountPrivilege") Required to create a computer account.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Add workstations to domain'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC078': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeManageVolumePrivilege",
       'description': '''Microsoft warns that "Use caution when assigning this user right. Users with this user right can explore disks and extend files in to memory that contains other data. When the extended files are opened, the user might be able to read and modify the acquired data."''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Manage the files on a volume / Perform volume maintenance tasks'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC079': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeRelabelPrivilege",
       'description': '''TODO SE_RELABEL_NAME TEXT("SeRelabelPrivilege") Required to modify the mandatory integrity level of an object.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Modify an object label'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC080': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeRestorePrivilege",
       'description': '''Some users have been granted the ability to write to any file or directory, even if object permissions don't allow it.  Specifically, check for the following permissions can be bypassed by the affected users: WRITE_DAC WRITE_OWNER ACCESS_SYSTEM_SECURITY FILE_GENERIC_WRITE FILE_ADD_FILE FILE_ADD_SUBDIRECTORY DELETE.  Note that it is therefore possible to change the owner or the DACL, meaning that read access is also possible.  This allows the affected users to take full control of any file or directory (but not services?).  This privilege is one of the prerequisites for users to be able to load backups of registry hives into the registry (RegLoadKey).  Note that this privilege is normally granted to members of the local administrators group and this does not infer a security weakness as the users have administration rights already.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Restore files and directories'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC081': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeShutdownPrivilege",
       'description': '''Some users are allowed to shut down the computer.  This may aid an attacker in exploiting a pre-existing vulnerability - e.g. after replacig a program that run at boot time.  Alone, it probably doesn't constitute a privilege escalation vector.  It could lead to desruption of the system, though.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Shut down the system'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC082': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeSyncAgentPrivilege",
       'description': '''TODO SE_SYNC_AGENT_NAME TEXT("SeSyncAgentPrivilege") Required for a domain controller to use the LDAP directory synchronization services. This privilege enables the holder to read all objects and properties in the directory, regardless of the protection on the objects and properties. By default, it is assigned to the Administrator and LocalSystem accounts on domain controllers.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Synchronize directory service data'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC083': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeTakeOwnershipPrivilege",
       'description': '''Some users have been granted the ability to take ownership of any object, even if object permissions don't grant them "Take Ownership" rights.  This allows the affected users to take full control of any object (file, directory, service, etc.).  This could trivially lead to the user escallating rights to local administrator.  Note that this privilege is normally granted to members of the local administrators group and this does not infer a security weakness as the users have administration rights already.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Take ownership of files or other objects'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC084': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeTcbPrivilege",
       'description': '''TODO SE_TCB_NAME TEXT("SeTcbPrivilege") This privilege identifies its holder as part of the trusted computer base. Some trusted protected subsystems are granted this privilege.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Act as part of the operating system'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC085': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeTrustedCredManAccessPrivilege",
       'description': '''TODO SE_TRUSTED_CREDMAN_ACCESS_NAME TEXT("SeTrustedCredManAccessPrivilege") Required to access Credential Manager as a trusted caller.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Access Credential Manager as a trusted caller'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC086': {
       'title': "Share Level Permissions Allow Access By Non-Admin Users",
       'description': '''The share-level permissions on some Windows file shares allows access by non-administrative users.  This can often be desirable, in which case this issue can be ignored.  However, sometimes it can allow data to be stolen or programs to be maliciously modified.  NB: Setting strong NTFS permissions can sometimes mean that data which seems to be exposed on a share actually isn't accessible.''',
       'recommendation': '''Review the share-level permissions that have been granted to non-administrative users and revoke access where possible.  Share-level permissions can be viewed in Windows Explorer: Right-click folder | Sharing and Security | "Sharing" tab | "Permissions" button (for XP - other OSs may vary slightly).''',
       'supporting_data': {
          'non_admin_shares': {
             'section': "description",
             'preamble': "The following non-admin users have been granted FILE_READ_DATA permission on shares:",
          },
       }
    },
    'WPC087': {
       'title': "Directory Creation Allowed On Drive Root",
       'description': '''Some of the local drive roots allow non-administrative users to create directories.  This could provide attackers with a place to stash hacking tools, or proive legitimacy to malware they are seeking to get other users to run.  It is relatively common to allow the creation of directories in the drive root, but it probably isn't required for normal operation.

NB: This issue has only been reported for NTFS filesystems.  Other non-NTFS file system may also allow this behaviour.  A separate issue is reported for non-NTFS filesystems.''',
       'recommendation': '''Modify the permissions on the drive roots to only allow administrators to create directories.  Revoke this permission from low-privileged users.''',
       'supporting_data': {
          'dir_add_dir': {
             'section': "description",
             'preamble': "The following drives allow non-administrative users to create directories in to their root:",
          },
       }
    },
    'WPC088': {
       'title': "Read Permissions Allowed On Event Log File",
       'description': '''Some of the Event Log files could be read by non-administrative users.  This may allow attackers to view log information they weren't intended to see.  This can help them to determine if they are being monitored or to access information which may help in other attacks.''',
       'recommendation': '''Modify the permissions on the above files to allow only administrators read access.  Revoke read access from low-privileged users.''',
       'supporting_data': {
          'file_read': {
             'section': "description",
             'preamble': "The files below could be changed by non-administrative users:",
          },
       }
    },
}

# TODO: Manage auditing and security log - view and clear security log.  Disable per-object auditing.
# TODO: Log on locally - low priv users can exec commands if they have physical access.  Not required for service accounts.  Too voluminous?