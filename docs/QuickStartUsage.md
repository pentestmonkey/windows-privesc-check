# Quick Start & Usage

This page describes basic usage of windows-privesc-check along with a few examples for common use cases.

Also the [main page](../README.md) for a high-level description of features.

## Quick Start

### Auditing the Local System

windows-privesc-check is best run on the system you want to audit.  There are a few less common use-cases where windows-privesc-check might be run over the network (see below).

Upload windows-privesc-check2.exe to the system you want to audit.

#### Run a Security Audit as Administrator

To most reliably find the highest number of security issues, run a security audit from an elevated command prompt:
```
C:>windows-privesc-check2.exe --audit -a -o wpc-report
```

The options means:
* `--audit`: run in audit mode.  Relatively little output.  Creates a report file (see below).  Identifies security issues.
* `-a`: Run all simple checks
* `-o`: File name stem for the reports.

The output report is saved in the current directory in the following formats:
* wpc-report.html - a list of security issues and appendices of relevant information in HTML format.  This report type is recommended for most use cases.
* wpc-report.txt  - a list of security issues in text format.  The type of report is not as well supported or as useful as the HTML format.
* wpc-report.xml  - everything from the HTML report, but in XML format.  This can be used to import results into your own tools and scripts.

#### Check for Privilege Escalation Vectors as a Non-administrative User

Use the same options as you would went running as an administrator:
```
C:\>windows-privesc-check2.exe --audit -a -o wpc-report
```

Some checks will fail as you lack permissions to do some of the checks.  Read wpc-report.html for a list of potential escalation vectors.

#### Dump Data about Securable Objects and other Security Settings

```
C:\>windows-privesc-check2.exe --dump -a > dump.txt
```

This will dump extremely verbose, human-readable data about the target system.  Make sure you redirect the output to a file.

```
C:\>windows-privesc-check2.exe --dumptab -a > dump.txt
```

This will dump extremely verbose, machine-readable data about the target system.  Tab-delimited format is used.  The meaning of each tab-delimited field is currently undocumented, but in many cases is obvious.

### Running Over the Network

windows-privesc-check cannot run any security checks (`--audit`) over the network.  However, it can dump a small amount of information that might be useful to penetration testers.

#### List Logged in Users

Listing logged on users required administrative privileges to the remote system.  The `-L` option lists logged in users.  It can be used either with current credentials or with new credentials:
```
C:\>windows-privesc-check2.exe --dump -L -s 10.0.0.1
C:\>windows-privesc-check2.exe --dump -L -s 10.0.0.1 -u administrator -p mypass -d mydomain
```

Output can be in human-readable (`--dump`) or machine-readable (`--dumptab`) format:
```
C:\>windows-privesc-check2.exe --dump -L -s 10.0.0.1
C:\>windows-privesc-check2.exe --dumptab -L -s 10.0.0.1
```

#### List Shares

Listing shares normally requires a valid account on the remote systems, but does not need administrative access.

```
C:\>windows-privesc-check2.exe --dump -H -s 10.0.0.1
C:\>windows-privesc-check2.exe --dump -H -s 10.0.0.1 -u administrator -p mypass -d mydomain
C:\>windows-privesc-check2.exe --dumptab -H -s 10.0.0.1 -u administrator -p mypass -d mydomain
```

#### List Users

Listing users normally requires a valid account on the remote systems, but does not need administrative access.
```
C:\>windows-privesc-check2.exe --dump -U -s 10.0.0.1
C:\>windows-privesc-check2.exe --dump -U -s 10.0.0.1 -u administrator -p mypass -d mydomain
C:\>windows-privesc-check2.exe --dumptab -U -s 10.0.0.1 -u administrator -p mypass -d mydomain
```

#### List Group Memberships

Listing groups members normally requires a valid account on the remote systems, but does not need administrative access.
```
C:\>windows-privesc-check2.exe --dump -G -s 10.0.0.1
C:\>windows-privesc-check2.exe --dump -G -s 10.0.0.1 -u administrator -p mypass -d mydomain
C:\>windows-privesc-check2.exe --dumptab -G -s 10.0.0.1 -u administrator -p mypass -d mydomain
```

## Usage

The quick-start guide above shows only a few of the main features.  A full list of options is shown below:
```
windows-privesc-check v2.0svn198 (http://pentestmonkey.net/windows-privesc-check)

Usage: C:\share\wpc2.exe (--dump [ dump opts] | --dumptab | --audit) [examine opts] [host opts] -o report-file-stem

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  --dump                Dumps info for you to analyse manually
  --dumptab             Dumps info in tab-delimited format
  --audit               Identify and report security weaknesses
  --pyshell             Start interactive python shell

  examine opts:
    At least one of these to indicate what to examine (*=not implemented)

    -a, --all           All Simple Checks (non-slow)
    -A, --allfiles      All Files and Directories (slow)
    -D, --drives        Drives
    -e, --reg_keys      Misc security-related reg keys
    -E, --eventlogs     Event Log*
    -f INTERESTING_FILE_LIST, --interestingfiledir=INTERESTING_FILE_LIST
                        Changes -A behaviour.  Look here INSTEAD
    -F INTERESTING_FILE_FILE, --interestingfilefile=INTERESTING_FILE_FILE
                        Changes -A behaviour.  Look here INSTEAD.  On dir per
                        line
    -G, --groups        Groups
    -H, --shares        Shares
    -I, --installed_software
                        Installed Software
    -j, --tasks         Scheduled Tasks
    -k, --drivers       Kernel Drivers
    -L, --loggedin      Logged In
    -O, --ntobjects     NT Objects
    -n, --nointerestingfiles
                        Changes -A/-f/-F behaviour.  Don't report interesting
                        files
    -N, --nounreadableif
                        Changes -A/-f/-F behaviour.  Report only interesting
                        files readable by untrsuted users (see -x, -X, -b, -B)
    -P, --progfiles     Program Files Directory Tree
    -r, --registry      Registry Settings + Permissions
    -R, --processes     Processes
    -S, --services      Windows Services
    -t, --paths         PATH
    -T PATCHFILE, --patches=PATCHFILE
                        Patches.  Arg is filename of xlsx patch info.
                        Download from
                        http://go.microsoft.com/fwlink/?LinkID=245778 or pass
                        'auto' to fetch automatically
    -U, --users         Users
    -v, --verbose       More verbose output on console
    -W, --errors        Die on errors instead of continuing (for debugging)
    -z, --noappendices  No report appendices in --audit mode

  host opts:
    Optional details about a remote host (experimental).  Default is
    current host.

    -s REMOTE_HOST, --server=REMOTE_HOST
                        Remote host or IP
    -u REMOTE_USER, --user=REMOTE_USER
                        Remote username
    -p REMOTE_PASS, --pass=REMOTE_PASS
                        Remote password
    -d REMOTE_DOMAIN, --domain=REMOTE_DOMAIN
                        Remote domain

  dump opts:
    Options to modify the behaviour of dump/dumptab mode

    -M, --get_modals    Dump password policy, etc.
    -V, --get_privs     Dump privileges for users/groups

  report opts:
    Reporting options

    -o REPORT_FILE_STEM, --report_file_stem=REPORT_FILE_STEM
                        Filename stem for txt, html report files
    -x IGNORE_PRINCIPAL_LIST, --ignoreprincipal=IGNORE_PRINCIPAL_LIST
                        Don't report privesc issues for these users/groups
    -X IGNORE_PRINCIPAL_FILE, --ignoreprincipalfile=IGNORE_PRINCIPAL_FILE
                        Don't report privesc issues for these users/groups
    -0, --ignorenoone   No one is trusted (even Admin, SYSTEM).  hyphen zero
    -c, --exploitablebycurrentuser
                        Report only privesc issues relating to current user
    -b EXPLOITABLE_BY_LIST, --exploitableby=EXPLOITABLE_BY_LIST
                        Report privesc issues only for these users/groups
    -B EXPLOITABLE_BY_FILE, --exploitablebyfile=EXPLOITABLE_BY_FILE
                        Report privesc issues only for these user/groupss
```
