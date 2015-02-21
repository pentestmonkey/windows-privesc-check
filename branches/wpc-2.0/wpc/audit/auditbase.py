import wpc.utils

class auditbase:
    def __init__(self, options):
        pass

    def run_sub(self, name, condition, sub, *args):
        if condition:
            if name:
                wpc.utils.section(name)
            #try:
            sub(*list(args))
            #except:
            #    print "[E] Errors occurred but were supressed.  Some checks might have been missed.  Probably a bug."
            #finally:
            #    if name:
            #        wpc.utils.print_major("Checks completed", 1)
        

