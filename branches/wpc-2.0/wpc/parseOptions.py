import wpc.utils
from optparse import OptionParser
from optparse import OptionGroup
import sys


def parseOptions():
    wpc.utils.print_banner()
    usage = "%s (--dump [ dump opts] |--audit) [examine opts] [host opts]" % (sys.argv[0])

    parser = OptionParser(usage=usage, version=wpc.utils.get_version())
    examine = OptionGroup(parser, "examine opts", "At least one of these to indicate what to examine")
    host = OptionGroup(parser, "host opts", "Optional details about a remote host (experimental).  Default is current host.")
    dump = OptionGroup(parser, "dump opts", "Options to modify the behaviour of dump mode")

    parser.add_option("--dump", dest="dump_mode", default=False, action="store_true", help="Dumps info for you to analyse manually")
    parser.add_option("--audit", dest="audit_mode", default=False, action="store_true", help="Identify and report security weaknesses")

    examine.add_option("-s", "--services",  dest="do_services", default=False, action="store_true", help="Windows Services")
    examine.add_option("-d", "--drivers",   dest="do_drivers", default=False, action="store_true", help="Kernel Drivers")
    examine.add_option("-P", "--processes", dest="do_processes", default=False, action="store_true", help="Processes")
    examine.add_option("-r", "--registry",  dest="do_registry", default=False, action="store_true", help="Registry Settings + Permissions")
    examine.add_option("-U", "--users",     dest="do_users", default=False, action="store_true", help="Users")
    examine.add_option("-G", "--groups",    dest="do_groups", default=False, action="store_true", help="Groups")

    host.add_option("-t", "--target", dest="remote_host", help="Remote host or IP")
    host.add_option("-u", "--user", dest="remote_user", help="Remote username")
    host.add_option("-p", "--pass", dest="remote_pass", help="Remote password")
    host.add_option("-D", "--domain", dest="remote_domain", help="Remote domain") 

    dump.add_option("-i", "--ignore_trusted", dest="ignore_trusted", default=False, action="store_true", help="Ignore ACEs for Trusted Users")
    dump.add_option("-m", "--get_members", dest="get_members", default=False, action="store_true", help="Dump group members (use with -G)")
    dump.add_option("-V", "--get_privs", dest="get_privs", default=False, action="store_true", help="Dump privileges for users/groups")

    parser.add_option_group(examine)
    parser.add_option_group(host)
    parser.add_option_group(dump)

    (options, args) = parser.parse_args()

    if not options.dump_mode and not options.audit_mode:
        print "[E] Specify either --dump or --audit.  -h for help."
        sys.exit()

    # TODO can't use -m without -G

    if not (options.do_services or options.do_drivers or options.do_processes or options.do_registry or options.do_users or options.do_groups):
        print "[E] Specify something to look at.  At least one of: -s, -d, -P, -r, -U, -G"
        sys.exit()

    return options
