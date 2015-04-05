Windows-privesc-check is standalone executable that runs on Windows systems.  It tries to find misconfigurations that could allow local unprivileged users to escalate privileges to other users or to access local apps (e.g. databases).  

It is written in python and converted to an executable using pyinstaller so it can be easily uploaded and run (as opposed to unzipping python + other dependencies).  It can run either as a normal user or as Administrator (obviously it does a better job when running as Administrator because it can read more files).

The latest version of the code is in the master branch.

# Use Cases 

## Find Privesc Vectors (as Administrator) 

When run with admin rights, windows-privesc-check has full read access to all [secureable objects](http://msdn.microsoft.com/en-us/library/aa379557%28VS.85%29.aspx).  This allows it to perform audits for escalation vectors such as:
  * Reconfiguring Windows Services
  * Replacing Service executables if they have weak file permissions
  * Replacing poorly protected .exe or .dll files in %ProgramFiles%
  * Tojaning the %PATH%
  * Maliciously modifying the registry (e.g. RunOnce)
  * Modifying programs on FAT file systems
  * Tampering with running processes

A great many of the privielges escalation vectors checked are simply checks for weak security descriptors on [Windows securable objects](http://msdn.microsoft.com/en-us/library/aa379557%28VS.85%29.aspx).

A report is generated in HTML, TXT and XML format.

## Find Privesc Vectors (as a Low-Privileged User)

An important design goal is that windows-privesc-check can perform as many checks as possible (above) without admin rights.  This will make the tool useful to pentesters as well as auditors.

Clearly, low-privileged users are unable to see certain parts of the registry and file system.  The tool is therefore inherently less able to identify security weaknesses when run as a low-privileged user.

As above, a report is generated in HTML, TXT and XML format.

## Dump Raw Auditing Data

Windows-privesc-check can simply dump raw data that it would normally use to identify security weaknesses.  This data can then analysed some other way - or simply stored as a snapshot of system security at the time of the audit.

Both human-readable (text) and machine readable (tab delimited) formats are supported.

Examples of data users are able to dump:
  * Detailed Share Information about local or remote systems.  Includes DACL (Share permissions).
  * Information about users, groups, memeberships and the Windows Privileges (e.g. SeBackupPrivilege).  See http://msdn.microsoft.com/en-us/library/bb530716%28v=VS.85%29.aspx.

## Provide Information To Help Compromise A Remote System

Given low-privileged credentials (or perhaps using anonymous access), windows-privesc-check should provide basic information which might help the user compromise the remote system.  This might include:
  * Details of poorly configure shares
  * A list of admin-equivalent users
  * Information about its domain membership and the trusts configured for that domain
