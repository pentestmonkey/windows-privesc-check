from wpc.parseOptions import parseOptions
from wpc.report.report import report
from wpc.audit.dump import dump
from wpc.audit.dumptab import dumptab
from wpc.audit.audit import audit
import datetime
import time
import wpc.utils
import sys

# ------------------------ Main Code Starts Here ---------------------

# Parse command line arguments
options = parseOptions()

# Initialise WPC
# TODO be able to enable/disable caching
wpc.utils.init(options)

# Object to hold all the issues we find
report = report()
wpc.utils.populate_scaninfo(report)
issues = report.get_issues()

if options.pyshell_mode:
    wpc.utils.printline("Python Shell - to exit do CTRL-z or type exit()")
    print
    import code
    code.interact(local=dict(globals(), **locals()))
    sys.exit()

wpc.utils.dump_options(options)

wpc.utils.printline("Starting Audit at %s" % datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S'))
start_time = time.time()

# Dump raw data if required
if options.dump_mode:
    d = dump(options)
    d.run()

# Dump raw data if required
if options.dumptab_mode:
    d = dumptab(options, report)
    d.run()

# Identify security issues
if options.audit_mode:
    a = audit(options, report)
    a.run()

    if options.report_file_stem:
        wpc.utils.printline("Audit Complete at %s" % datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S'))
        print
        print "[+] Runtime: %.1f seconds" % int(time.time() - start_time)
        print
        
        filename = "%s.xml" % options.report_file_stem
        print "[+] Saving report file %s" % filename
        f = open(filename, 'w')
        f.write(report.as_xml_string())
        f.close()

        filename = "%s.txt" % options.report_file_stem
        print "[+] Saving report file %s" % filename
        f = open(filename, 'w')
        f.write(report.as_text())
        f.close()

        filename = "%s.html" % options.report_file_stem
        print "[+] Saving report file %s" % filename
        f = open(filename, 'w')
        f.write(report.as_html())
        f.close()

    #wpc.conf.cache.print_stats()
