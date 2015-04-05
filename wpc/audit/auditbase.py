import wpc.utils

class auditbase:
    def __init__(self, options):
        self.options = options

    def run_sub(self, name, condition, sub, *args):
        if condition:
            if name:
                wpc.utils.section(name)
                
            if self.options.do_errors:
                sub(*list(args))
                if name:
                    wpc.utils.print_major("Checks completed", 1)
            else:
                try:
                    sub(*list(args))
                except:
                    print "[E] Errors occurred but were supressed.  Some checks might have been missed.  Probably a bug."
                finally:
                    if name:
                        wpc.utils.print_major("Checks completed", 1)
        

