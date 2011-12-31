from wpc.share import share
import win32net
import wpc.conf


class shares:
    def __init__(self):
        self.shares = []
        pass

    def get_all(self):
        if self.shares == []:
            resume = 1;
            while resume:
                resume = 0
                sharelist = None
                try:
                    (sharelist, total, resume) = win32net.NetShareEnum(wpc.conf.remote_server, 0, resume, 9999)
                except:
                    print "[E] Can't check shares - not enough privs?"

                if sharelist:
                    for shareitem in sharelist:
                        s = share(shareitem['netname'])
                        self.shares.append(s)

        return self.shares