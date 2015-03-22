# What Windows-privesc-check is supposed to do #

## Find Privesc Vectors (as Administrator) ##

When run with admin rights, windows-privesc-check has full read access to all secureable objects.  This allows it to perform audits for escalation vectors such as:
  * Reconfiguring Windows Services
  * Replacing Service executables if they have weak file permissions
  * Replacing poorly protected .exe or .dll files in %ProgramFiles%
  * Tojaning the %PATH%
  * Maliciously modifying the registry (e.g. RunOnce)
  * Tampering with Event Logs
  * Modifying programs on FAT file systems
  * Tampering with running processes

Securable Objects: http://msdn.microsoft.com/en-us/library/aa379557%28VS.85%29.aspx

## Find Privesc Vectors (as Low-priv Use) ##

An important design goal is that windows-privesc-check can perform as many checks as possible (above) without admin rights.  This will make the tool useful to pentesters as well as auditors.

Clearly, low-privileged users are unable to see certain parts of the registry and file system.  The tool is therefore inherently less able when run as a low-priv user.

## Dump Raw Auditing Data ##

This is currently an experimental feature that allows the use to dump some raw data.  They can then analyse the data in the way they choose instead of relying on windows-privesc-check.

Examples of data users are able to dump:
  * Detailed Share Information about local or remote systems.  Includes DACL (Share permissions).
  * Information about users, groups, memeberships and the Windows Privileges (e.g. SeBackupPrivilege).  See http://msdn.microsoft.com/en-us/library/bb530716%28v=VS.85%29.aspx.

Example data users might be able to dump in future:
  * Values and permission for important registry keys
  * Information about Windows services including executable names, file permissions, service permissions

## Produce a Readable HTML Report ##

A report can already be produced contain privesc vectors.  This works whether its run with or without admin privileges.

## Produce Parsable XML Report ##

This feature hasn't even been started yet.

## Provide Information To Help Compromise A Remote System ##

This feature has barely been started.

Given low-privileged credentials (or perhaps using anonymous access), windows-privesc-check should provide basic information which might help the user compromise the remote system.  This might include:
  * Details of poorly configure shares
  * A list of admin-equivalent users
  * Information about its domain membership and the trusts configured for that domain