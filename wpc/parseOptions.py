import wpc.utils
from optparse import OptionParser
from optparse import OptionGroup
import sys

def parseOptions():
    wpc.utils.print_banner()
    usage = "%s (--dump [ dump opts] |--audit) [examine opts] [host opts] -o report-file-stem" % (sys.argv[0])

    parser  = OptionParser(usage = usage, version = wpc.utils.get_version())
    examine = OptionGroup(parser, "examine opts", "At least one of these to indicate what to examine (*=not implemented)")
    host    = OptionGroup(parser, "host opts", "Optional details about a remote host (experimental).  Default is current host.")
    dump    = OptionGroup(parser, "dump opts", "Options to modify the behaviour of dump mode")
    report  = OptionGroup(parser, "report opts", "Reporting options")

    parser.add_option("--dump",  dest = "dump_mode", default = False, action = "store_true", help = "Dumps info for you to analyse manually")
    parser.add_option("--audit", dest = "audit_mode", default = False, action = "store_true", help = "Identify and report security weaknesses")

    examine.add_option("-a", "--all",       dest = "do_all",           default = False, action = "store_true", help = "All Simple Checks (non-slow)")
    examine.add_option("-t", "--paths",     dest = "do_paths",         default = False, action = "store_true", help = "PATH")
    examine.add_option("-D", "--drives",    dest = "do_drives",        default = False, action = "store_true", help = "Drives*")
    examine.add_option("-E", "--eventlogs", dest = "do_eventlogs",     default = False, action = "store_true", help = "Event Log*")
    examine.add_option("-H", "--shares",    dest = "do_shares",        default = False, action = "store_true", help = "Shares*")
    examine.add_option("-T", "--patches",   dest = "patchfile",                                                help = "Patches.  Arg is filename of xlsx patch info.  Download from http://go.microsoft.com/fwlink/?LinkID=245778 or pass 'auto' to fetch automatically")
    examine.add_option("-L", "--loggedin",  dest = "do_loggedin",      default = False, action = "store_true", help = "Logged In*")
    examine.add_option("-S", "--services",  dest = "do_services",      default = False, action = "store_true", help = "Windows Services")
    examine.add_option("-k", "--drivers",   dest = "do_drivers",       default = False, action = "store_true", help = "Kernel Drivers")
    examine.add_option("-R", "--processes", dest = "do_processes",     default = False, action = "store_true", help = "Processes")
    examine.add_option("-P", "--progfiles", dest = "do_program_files", default = False, action = "store_true", help = "Program Files Directory Tree")
    examine.add_option("-r", "--registry",  dest = "do_registry",      default = False, action = "store_true", help = "Registry Settings + Permissions")
    examine.add_option("-j", "--tasks",     dest = "do_scheduled_tasks", default = False, action = "store_true", help = "Scheduled Tasks")
    examine.add_option("-U", "--users",     dest = "do_users",         default = False, action = "store_true", help = "Users")
    examine.add_option("-G", "--groups",    dest = "do_groups",        default = False, action = "store_true", help = "Groups")
    examine.add_option("-A", "--allfiles",  dest = "do_allfiles",      default = False, action = "store_true", help = "All Files and Directories (slow)")
    examine.add_option("-e", "--reg_keys",  dest = "do_reg_keys",      default = False, action = "store_true", help = "Misc security-related reg keys")
    examine.add_option("-v", "--verbose",   dest = "verbose",          default = False, action = "store_true", help = "More verbose output on console")

    host.add_option("-s", "--server", dest = "remote_host",   help = "Remote host or IP")
    host.add_option("-u", "--user",   dest = "remote_user",   help = "Remote username")
    host.add_option("-p", "--pass",   dest = "remote_pass",   help = "Remote password")
    host.add_option("-d", "--domain", dest = "remote_domain", help = "Remote domain")

    dump.add_option("-i", "--ignore_trusted", dest = "ignore_trusted", default = False, action = "store_true", help = "Ignore ACEs for Trusted Users")
    dump.add_option("-m", "--get_members",    dest = "get_members",    default = False, action = "store_true", help = "Dump group members (use with -G)")
    dump.add_option("-M", "--get_modals",     dest = "get_modals",     default = False, action = "store_true", help = "Dump password policy, etc.")
    dump.add_option("-V", "--get_privs",      dest = "get_privs",      default = False, action = "store_true", help = "Dump privileges for users/groups")

    report.add_option("-o", "--report_file_stem",  dest = "report_file_stem",  default = False, help = "Filename stem for txt, html report files")

    parser.add_option_group(examine)
    parser.add_option_group(host)
    parser.add_option_group(dump)
    parser.add_option_group(report)

    (options, args) = parser.parse_args()

    if options.audit_mode and not options.report_file_stem:
        print "[E] Specify report filename stem, e.g. '-o report-myhost'.  -h for help."
        sys.exit()

    # TODO check file is writable.

    if not options.dump_mode and not options.audit_mode:
        print "[E] Specify either --dump or --audit.  -h for help."
        sys.exit()

    # TODO can't use -m without -G

    if not (options.do_all or options.do_services or options.do_drivers or options.do_processes or options.patchfile or options.do_reg_keys or options.do_registry or options.do_users or options.do_groups or options.do_program_files or options.do_paths or options.do_drives or options.do_eventlogs or options.do_shares or options.do_loggedin or options.do_users or options.do_groups or options.do_allfiles or options.get_modals or options.do_scheduled_tasks):
        print "[E] Specify something to look at.  At least one of: -a, -j, -t, -D, -E, -e, -H, -T, -L , -S, -k, -I, -U, -s, -d, -P, -r, -R, -U, -G, -M.  -h for help."
        sys.exit()

    return options
