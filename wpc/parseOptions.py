import wpc.utils
from optparse import OptionParser
from optparse import OptionGroup
import sys

def parseOptions():
    wpc.utils.print_banner()
    usage = "%s (--dump [ dump opts] | --dumptab | --audit) [examine opts] [host opts] -o report-file-stem" % (sys.argv[0])

    parser  = OptionParser(usage = usage, version = wpc.utils.get_version())
    examine = OptionGroup(parser, "examine opts", "At least one of these to indicate what to examine (*=not implemented)")
    host    = OptionGroup(parser, "host opts", "Optional details about a remote host (experimental).  Default is current host.")
    dump    = OptionGroup(parser, "dump opts", "Options to modify the behaviour of dump/dumptab mode")
    report  = OptionGroup(parser, "report opts", "Reporting options")

    parser.add_option("--dump",     dest = "dump_mode",   default = False, action = "store_true", help = "Dumps info for you to analyse manually")
    parser.add_option("--dumptab",  dest = "dumptab_mode",default = False, action = "store_true", help = "Dumps info in tab-delimited format")
    parser.add_option("--audit",    dest = "audit_mode",  default = False, action = "store_true", help = "Identify and report security weaknesses")
    parser.add_option("--pyshell",  dest = "pyshell_mode",  default = False, action = "store_true", help = "Start interactive python shell")

    examine.add_option("-a", "--all",       dest = "do_all",           default = False, action = "store_true", help = "All Simple Checks (non-slow)")
    examine.add_option("-A", "--allfiles",  dest = "do_allfiles",      default = False, action = "store_true", help = "All Files and Directories (slow)")
    examine.add_option("-D", "--drives",    dest = "do_drives",        default = False, action = "store_true", help = "Drives")
    examine.add_option("-e", "--reg_keys",  dest = "do_reg_keys",      default = False, action = "store_true", help = "Misc security-related reg keys")
    examine.add_option("-E", "--eventlogs", dest = "do_eventlogs",     default = False, action = "store_true", help = "Event Log*")
    examine.add_option("-f", "--interestingfiledir", dest = "interesting_file_list", default = [],    action = "append",    help = "Changes -A behaviour.  Look here INSTEAD")
    examine.add_option("-F", "--interestingfilefile",dest = "interesting_file_file", default = False,                       help = "Changes -A behaviour.  Look here INSTEAD.  On dir per line")
    examine.add_option("-G", "--groups",    dest = "do_groups",        default = False, action = "store_true", help = "Groups")
    examine.add_option("-H", "--shares",    dest = "do_shares",        default = False, action = "store_true", help = "Shares")
    examine.add_option("-I", "--installed_software", dest = "do_installed_software", default = False, action = "store_true", help = "Installed Software")
    examine.add_option("-j", "--tasks",     dest = "do_scheduled_tasks", default = False, action = "store_true", help = "Scheduled Tasks")
    examine.add_option("-k", "--drivers",   dest = "do_drivers",       default = False, action = "store_true", help = "Kernel Drivers")
    examine.add_option("-L", "--loggedin",  dest = "do_loggedin",      default = False, action = "store_true", help = "Logged In")
    examine.add_option("-O", "--ntobjects", dest = "do_nt_objects",    default = False, action = "store_true", help = "NT Objects")
    examine.add_option("-n", "--nointerestingfiles", dest = "do_interesting_files",default = True, action = "store_false", help = "Changes -A/-f/-F behaviour.  Don't report interesting files")
    examine.add_option("-N", "--nounreadableif",     dest = "do_unreadable_if",    default = True, action = "store_false", help = "Changes -A/-f/-F behaviour.  Report only interesting files readable by untrsuted users (see -x, -X, -b, -B)")
    examine.add_option("-P", "--progfiles", dest = "do_program_files", default = False, action = "store_true", help = "Program Files Directory Tree")
    examine.add_option("-r", "--registry",  dest = "do_registry",      default = False, action = "store_true", help = "Registry Settings + Permissions")
    examine.add_option("-R", "--processes", dest = "do_processes",     default = False, action = "store_true", help = "Processes")
    examine.add_option("-S", "--services",  dest = "do_services",      default = False, action = "store_true", help = "Windows Services")
    examine.add_option("-t", "--paths",     dest = "do_paths",         default = False, action = "store_true", help = "PATH")
    examine.add_option("-T", "--patches",   dest = "patchfile",                                                help = "Patches.  Arg is filename of xlsx patch info.  Download from http://go.microsoft.com/fwlink/?LinkID=245778 or pass 'auto' to fetch automatically")
    examine.add_option("-U", "--users",     dest = "do_users",         default = False, action = "store_true", help = "Users")
    examine.add_option("-v", "--verbose",   dest = "verbose",          default = False, action = "store_true", help = "More verbose output on console")
    examine.add_option("-W", "--errors",    dest = "do_errors",        default = False, action = "store_true", help = "Die on errors instead of continuing (for debugging)")
    examine.add_option("-z", "--noappendices",dest = "do_appendices",  default = True,  action = "store_false",help = "No report appendices in --audit mode")

    host.add_option("-s", "--server", dest = "remote_host",   help = "Remote host or IP")
    host.add_option("-u", "--user",   dest = "remote_user",   help = "Remote username")
    host.add_option("-p", "--pass",   dest = "remote_pass",   help = "Remote password")
    host.add_option("-d", "--domain", dest = "remote_domain", help = "Remote domain")

    dump.add_option("-M", "--get_modals",     dest = "get_modals",     default = False, action = "store_true", help = "Dump password policy, etc.")
    dump.add_option("-V", "--get_privs",      dest = "get_privs",      default = False, action = "store_true", help = "Dump privileges for users/groups")

    # Running out of letters for short options.  Here's a list of ones used
    #    abcdefghijklmnopqrstuvwxyz
    # uc xxxxxx  xxx xxxx xxxxx x 
    # lc xx xxxxx   x xxx xxxxxxx x 
    
    report.add_option("-o", "--report_file_stem",         dest = "report_file_stem",      default = False,                       help = "Filename stem for txt, html report files")
    report.add_option("-x", "--ignoreprincipal",          dest = "ignore_principal_list", default = [],    action = "append",    help = "Don't report privesc issues for these users/groups")
    report.add_option("-X", "--ignoreprincipalfile",      dest = "ignore_principal_file", default = False,                       help = "Don't report privesc issues for these users/groups")
    report.add_option("-0", "--ignorenoone",              dest = "ignorenoone",           default = False, action = "store_true",help = "No one is trusted (even Admin, SYSTEM).  hyphen zero")
    report.add_option("-c", "--exploitablebycurrentuser", dest = "exploitable_by_me",     default = False, action = "store_true",help = "Report only privesc issues relating to current user")
    report.add_option("-b", "--exploitableby",            dest = "exploitable_by_list",   default = [],    action = "append",    help = "Report privesc issues only for these users/groups")
    report.add_option("-B", "--exploitablebyfile",        dest = "exploitable_by_file",   default = False,                       help = "Report privesc issues only for these user/groupss")

    parser.add_option_group(examine)
    parser.add_option_group(host)
    parser.add_option_group(dump)
    parser.add_option_group(report)

    (options, _) = parser.parse_args()

    if not options.dump_mode and not options.audit_mode and not options.dumptab_mode and not options.pyshell_mode:
        print "[E] Specify mode using --dump, --audit, --dumptab or --pyshell.  -h for help."
        sys.exit()

    if options.dump_mode or options.audit_mode or options.dumptab_mode:
        if not (options.do_all or options.do_services or options.do_drivers or options.do_processes or options.patchfile or options.do_reg_keys or options.do_registry or options.do_users or options.do_groups or options.do_program_files or options.do_paths or options.do_drives or options.do_eventlogs or options.do_shares or options.do_loggedin or options.do_users or options.do_groups or options.do_allfiles or options.get_modals or options.do_scheduled_tasks or options.do_nt_objects or options.do_installed_software or options.interesting_file_list or options.interesting_file_file):
            print "[E] Specify something to look at.  At least one of: -a, -j, -O, -t, -D, -E, -e, -H, -T, -L , -S, -k, -I, -U, -s, -d, -P, -r, -R, -U, -G, -M.  -h for help."
            sys.exit()
    
        if options.ignorenoone and not (options.ignore_principal_list or options.ignore_principal_file):
            print "[W] -0 (--ignorenoone) specified without -x or -X.  This is a crazy thing to do in --audit mode.  Output of --dump/--dumptab will be huge!"
            
        if options.audit_mode and not options.report_file_stem:
            print "[E] Specify report filename stem, e.g. '-o report-myhost'.  -h for help."
            sys.exit()
    
        if options.exploitable_by_me and (options.ignore_principal_list or options.ignore_principal_file or options.exploitable_by_list or options.exploitable_by_file):
            print "[E] When using -c, it doesn't make sense to use -x, -X, -b or -B"
            sys.exit()
            
        if (options.ignore_principal_list or options.ignore_principal_file) and (options.exploitable_by_list or options.exploitable_by_file):
            print "[E] When using -b or -B, it doesn't make sense to use -x or -X"
            sys.exit()
        
        # TODO check file is writable.
        # TODO can't use -m without -G
    
    return options
