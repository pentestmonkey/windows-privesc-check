from wpc.principal import principal
from wpc.sd import sd
import ntsecuritycon
import win32security
import wpc.conf


class token:
    def __init__(self, th):
        self.th = th  # token handle
        self.token_type = None
        self.token_groups = []
        self.token_origin = None
        self.token_source = None
        self.token_restrictions = None
        self.token_elevation_type = None
        self.token_ui_access = None
        self.token_linked_token = None
        self.token_logon_sid = None
        self.token_elevation = None
        self.token_integrity_level = None
        self.token_mandatory_policy = None
        self.token_restricted_sids = []
        self.token_impersonation_level = None
        self.token_restricted = None
        self.token_user = None
        self.token_primary_group = None
        self.token_owner = None
        self.token_privileges = []
        self.sd = None
        pass

    def get_th(self):
        return self.th

    def get_th_int(self):
        return int(self.th)

    def get_sd(self):
        if not self.sd:
            try:
                # TODO also get mandatory label
                secdesc = win32security.GetSecurityInfo(self.get_th(), win32security.SE_KERNEL_OBJECT, win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION | win32security.GROUP_SECURITY_INFORMATION)
                self.sd = sd('token', secdesc)
            except:
                pass
        return self.sd

    def get_token_groups(self):
        if self.token_groups == []:
            try:
                for tup in win32security.GetTokenInformation(self.get_th(), ntsecuritycon.TokenGroups):
                    sid = tup[0]
                    attr = tup[1]
                    if attr < 0:
                        attr = 2 ** 32 + attr
                    attr_str_a = []
                    if attr & 1:
                        attr_str_a.append("MANDATORY")
                    if attr & 2:
                        attr_str_a.append("ENABLED_BY_DEFAULT")
                    if attr & 4:
                        attr_str_a.append("ENABLED")
                    if attr & 8:
                        attr_str_a.append("OWNER")
                    if attr & 16:
                        attr_str_a.append("USE_FOR_DENY_ONLY")
                    if attr & 0x00000020:
                        attr_str_a.append("INTEGRITY")
                    if attr & 0x00000040:
                        attr_str_a.append("INTEGRITY_ENABLED")
                    if attr & 0x20000000:
                        attr_str_a.append("RESOURCE")
                    if attr & 0xC0000000:
                        attr_str_a.append("LOGON_ID")
                    self.token_groups.append((principal(sid), attr_str_a))
            except:
                pass
        return self.token_groups

    def get_token_origin(self):
        if not self.token_origin and self.get_th():
            self.token_origin = win32security.GetTokenInformation(self.get_th(), ntsecuritycon.TokenOrigin)
        return self.token_origin

    def get_token_source(self):
        if not self.token_source and self.get_th():
            try:
                self.token_source = win32security.GetTokenInformation(self.get_th(), ntsecuritycon.TokenSource)
            except:
                pass
        return self.token_source

    def get_token_impersonation_level(self):
        if not self.token_impersonation_level and self.get_th():
            try:
                self.token_impersonation_level = win32security.GetTokenInformation(self.get_th(), ntsecuritycon.TokenImpersonationLevel)
                if self.token_impersonation_level is None:
                    return "[N/A not impersonating]"
                if self.token_impersonation_level >=0 and self.token_impersonation_level <= 3:
                    return wpc.conf.SECURITY_IMPERSONATION_LEVEL[self.token_impersonation_level]
            except:
                pass
        return self.token_impersonation_level

    def get_token_restrictions(self):
        if not self.token_restrictions and self.get_th():
            try:
                self.token_restrictions = win32security.GetTokenInformation(self.get_th(), ntsecuritycon.TokenHasRestrictions)
            except:
                pass
        return self.token_restrictions

    def get_token_restricted_sids(self):
        if self.token_restricted_sids == [] and self.get_th():
            try:
                tups = win32security.GetTokenInformation(self.get_th(), ntsecuritycon.TokenRestrictedSids)
                for sid, i in tups:
                    self.token_restricted_sids.append(principal(sid))
            except:
                pass
        return self.token_restricted_sids

    def get_token_elevation_type(self):
        if not self.token_elevation_type and self.get_th():
            try:
                self.token_elevation_type = win32security.GetTokenInformation(self.get_th(), ntsecuritycon.TokenElevationType)
                if self.token_elevation_type == 1:
                    self.token_elevation_type = "TokenElevationTypeDefault"
                elif self.token_elevation_type == 2:
                    self.token_elevation_type = "TokenElevationTypeFull"
                elif self.token_elevation_type == 3:
                    self.token_elevation_type = "TokenElevationTypeLimited"
                else:
                    self.token_elevation_type = "Unknown (%s)" % self.token_elevation_type
            except:
                pass
        return self.token_elevation_type

    def get_token_ui_access(self):
        if not self.token_ui_access and self.get_th():
            try:
                self.token_ui_access = win32security.GetTokenInformation(self.get_th(), ntsecuritycon.TokenUIAccess)
            except:
                pass
        return self.token_ui_access

    def get_token_linked_token(self):
        if not self.token_linked_token and self.get_th():
            try:
                self.token_linked_token = win32security.GetTokenInformation(self.get_th(), ntsecuritycon.TokenLinkedToken)
            except:
                pass
        return self.token_linked_token

    def get_token_logon_sid(self):
        if not self.token_logon_sid and self.get_th():
            try:
                self.token_logon_sid = win32security.GetTokenInformation(self.get_th(), ntsecuritycon.TokenLogonSid)
            except:
                pass
        return self.token_logon_sid

    def get_token_elevation(self):
        if not self.token_elevation and self.get_th():
            try:
                self.token_elevation = win32security.GetTokenInformation(self.get_th(), ntsecuritycon.TokenElevation)
            except:
                pass
        return self.token_elevation

    def get_token_integrity_level(self):
        if not self.token_integrity_level and self.get_th():
            try:
                sid, i = win32security.GetTokenInformation(self.get_th(), ntsecuritycon.TokenIntegrityLevel)
                self.token_integrity_level = principal(sid)
            except:
                pass
        return self.token_integrity_level

    def get_token_mandatory_policy(self):
        if not self.token_mandatory_policy and self.get_th():
            try:
                m = win32security.GetTokenInformation(self.get_th(), ntsecuritycon.TokenMandatoryPolicy)

                if m == 0:
                    m = "OFF"
                elif m == 1:
                    m = "NO_WRITE_UP"
                elif m == 2:
                    m = "NEW_PROCESS_MIN"
                elif m == 3:
                    m = "POLICY_VALID_MASK"
                else:
                    m = str(m)
                self.token_mandatory_policy = m
            except:
                pass
        return self.token_mandatory_policy

    def get_token_type(self):
        if not self.token_type == [] and self.get_th():
            try:
                tokentype = win32security.GetTokenInformation(self.get_th(), ntsecuritycon.TokenType)
                tokentype_str = "TokenImpersonation"
                if tokentype == 1:
                    tokentype_str = "TokenPrimary"
                self.token_type = tokentype_str
            except:
                pass
        return self.token_type

    def get_token_restricted(self):
        if not self.token_restricted and self.get_th():
            try:
                self.token_restricted = win32security.IsTokenRestricted(self.get_th())
            except:
                pass
        return self.token_restricted

    # Link that explains how privs are added / removed from tokens:
    # http://support.microsoft.com/kb/326256
    def get_token_privileges(self):
        if self.token_privileges == [] and self.get_th():
            #try:
                privs = win32security.GetTokenInformation(self.get_th(), ntsecuritycon.TokenPrivileges)

                for priv_tuple in privs:
                    attr_str_a = []
                    priv_val = priv_tuple[0]
                    attr = priv_tuple[1]
                    attr_str = "unknown_attr(" + str(attr) + ")"
                    if attr == 0:
                        attr_str_a.append("[disabled but not removed]")
                    if attr & 1:
                        attr_str_a.append("ENABLED_BY_DEFAULT")
                    if attr & 2:
                        attr_str_a.append("ENABLED")
                    if attr & 0x80000000:
                        attr_str_a.append("USED_FOR_ACCESS")
                    if attr & 4:
                        attr_str_a.append("REMOVED")

                    self.token_privileges.append((win32security.LookupPrivilegeName(wpc.conf.remote_server, priv_val), attr_str_a))

            #except:
            #    pass
        return self.token_privileges

    def get_token_user(self):
        if not self.token_user and self.get_th():
            sidObj, intVal = win32security.GetTokenInformation(self.get_th(), ntsecuritycon.TokenUser)
            if sidObj:
                self.token_user = principal(sidObj)
        return self.token_user

    def get_token_primary_group(self):
        if not self.token_primary_group and self.get_th():
            sidObj = win32security.GetTokenInformation(self.get_th(), ntsecuritycon.TokenPrimaryGroup)
            if sidObj:
                self.token_primary_group = principal(sidObj)
        return self.token_primary_group

    def get_token_owner(self):
        if not self.token_owner and self.get_th():
            sidObj = win32security.GetTokenInformation(self.get_th(), ntsecuritycon.TokenOwner)
            if sidObj:
                self.token_owner = principal(sidObj)
        return self.token_owner

    def as_text_no_rec(self):
        t = '--- Start Access Token ---\n'

        if self.get_th():
            t += "Token Handle: %s\n" % self.get_th()
        if self.get_token_owner():
            t += "Token Owner: " + str(self.get_token_owner().get_fq_name()) + "\n"
        if self.get_token_user():
            t += "Token User: " + str(self.get_token_user().get_fq_name()) + "\n"
        if self.get_token_primary_group():
            t += "Token Group: " + str(self.get_token_primary_group().get_fq_name()) + "\n"
        t += "Token Type: " + str(self.get_token_type()) + "\n"
        t += "TokenImpersonationLevel: " + str(self.get_token_impersonation_level()) + "\n"
        t += "Token Origin: " + str(self.get_token_origin()) + "\n"
        t += "Token Source: " + str(self.get_token_source()) + "\n"
        t += "TokenHasRestrictions: " + str(self.get_token_restrictions()) + "\n"
        t += "TokenElevationType: " + str(self.get_token_elevation_type()) + "\n"
        t += "TokenUIAccess: " + str(self.get_token_ui_access()) + "\n"
        t += "TokenLinkedToken: " + str(self.get_token_linked_token()) + "\n"
        t += "TokenLogonSid: " + str(self.get_token_logon_sid()) + "\n"
        t += "TokenElevation: " + str(self.get_token_elevation()) + "\n"
        t += "TokenIntegrityLevel: " + str(self.get_token_integrity_level().get_fq_name()) + "\n"
        t += "TokenMandatoryPolicy: " + str(self.get_token_mandatory_policy()) + "\n"
        t += "Token Resitrcted Sids:\n"
        for sid in self.get_token_restricted_sids():
            t += "\t" + sid.get_fq_name() + "\n"
        t += "IsTokenRestricted: " + str(self.get_token_restricted()) + "\n"
        t += "Token Groups:\n"
        for g, attr_a in self.get_token_groups():
            t += "\t%s: %s\n" % (g.get_fq_name(), "|".join(attr_a))
        if self.get_token_linked_token():
            t += token(self.get_token_linked_token()).as_text_no_rec2()
        t += '--- End Access Token ---\n'
        return t

    def as_text_no_rec3(self):
        t = '--- Start Access Token ---\n'

        if self.get_token_owner():
            t += "Token Owner: " + str(self.get_token_owner().get_fq_name()) + "\n"
        if self.get_token_user():
            t += "Token User: " + str(self.get_token_user().get_fq_name()) + "\n"
        if self.get_token_primary_group():
            t += "Token Group: " + str(self.get_token_primary_group().get_fq_name()) + "\n"
        t += "Token Type: " + str(self.get_token_type()) + "\n"
        t += "TokenImpersonationLevel: " + str(self.get_token_impersonation_level()) + "\n"
        t += "Token Origin: " + str(self.get_token_origin()) + "\n"
        t += "Token Source: " + str(self.get_token_source()) + "\n"
        t += "TokenHasRestrictions: " + str(self.get_token_restrictions()) + "\n"
        t += "TokenElevationType: " + str(self.get_token_elevation_type()) + "\n"
        t += "TokenUIAccess: " + str(self.get_token_ui_access()) + "\n"
        t += "TokenLinkedToken: " + str(self.get_token_linked_token()) + "\n"
        #if self.get_token_linked_token():
        #    t += token(self.get_token_linked_token()).as_text_no_rec2()
        t += "TokenLogonSid: " + str(self.get_token_logon_sid()) + "\n"
        t += "TokenElevation: " + str(self.get_token_elevation()) + "\n"
        t += "TokenIntegrityLevel: " + str(self.get_token_integrity_level().get_fq_name()) + "\n"
        t += "TokenMandatoryPolicy: " + str(self.get_token_mandatory_policy()) + "\n"
        t += "Token Resitrcted Sids:\n"
        for sid in self.get_token_restricted_sids():
            t += "\t" + sid.get_fq_name() + "\n"
        t += "IsTokenRestricted: " + str(self.get_token_restricted()) + "\n"
        t += "Token Groups:\n"
        for g, attr_a in self.get_token_groups():
            t += "\t%s: %s\n" % (g.get_fq_name(), "|".join(attr_a))
        t += '--- End Access Token ---\n'
        return t

    def as_text_no_rec2(self):
        t = '--- Start Access Token ---\n'

        if self.get_token_owner():
            t += "Token Owner: " + str(self.get_token_owner().get_fq_name()) + "\n"
        if self.get_token_user():
            t += "Token User: " + str(self.get_token_user().get_fq_name()) + "\n"
        if self.get_token_primary_group():
            t += "Token Group: " + str(self.get_token_primary_group().get_fq_name()) + "\n"
        t += "Token Type: " + str(self.get_token_type()) + "\n"
        t += "TokenImpersonationLevel: " + str(self.get_token_impersonation_level()) + "\n"
        t += "Token Origin: " + str(self.get_token_origin()) + "\n"
        t += "Token Source: " + str(self.get_token_source()) + "\n"
        t += "TokenHasRestrictions: " + str(self.get_token_restrictions()) + "\n"
        t += "TokenElevationType: " + str(self.get_token_elevation_type()) + "\n"
        t += "TokenUIAccess: " + str(self.get_token_ui_access()) + "\n"
        t += "TokenLinkedToken: " + str(self.get_token_linked_token()) + "\n"
        if self.get_token_linked_token():
            t += token(self.get_token_linked_token()).as_text_no_rec3()
        t += "TokenLogonSid: " + str(self.get_token_logon_sid()) + "\n"
        t += "TokenElevation: " + str(self.get_token_elevation()) + "\n"
        t += "TokenIntegrityLevel: " + str(self.get_token_integrity_level().get_fq_name()) + "\n"
        t += "TokenMandatoryPolicy: " + str(self.get_token_mandatory_policy()) + "\n"
        t += "Token Resitrcted Sids:\n"
        for sid in self.get_token_restricted_sids():
            t += "\t" + sid.get_fq_name() + "\n"
        t += "IsTokenRestricted: " + str(self.get_token_restricted()) + "\n"
        t += "Token Groups:\n"
        for g, attr_a in self.get_token_groups():
            t += "\t%s: %s\n" % (g.get_fq_name(), "|".join(attr_a))
        t += '--- End Access Token ---\n'
        return t

    def as_text(self):
        t = '--- Start Access Token ---\n'

        if self.get_th_int():
            t += "Token Handle: %s\n" % int(self.get_th_int())
        if self.get_token_owner():
            t += "Token Owner: " + str(self.get_token_owner().get_fq_name()) + "\n"
        if self.get_token_user():
            t += "Token User: " + str(self.get_token_user().get_fq_name()) + "\n"
        if self.get_token_primary_group():
            t += "Token Group: " + str(self.get_token_primary_group().get_fq_name()) + "\n"
        t += "Token Type: " + str(self.get_token_type()) + "\n"
        t += "TokenImpersonationLevel: " + str(self.get_token_impersonation_level()) + "\n"
        t += "Token Origin: " + str(self.get_token_origin()) + "\n"
        t += "Token Source: " + str(self.get_token_source()) + "\n"
        t += "TokenHasRestrictions: " + str(self.get_token_restrictions()) + "\n"
        t += "TokenElevationType: " + str(self.get_token_elevation_type()) + "\n"
        t += "TokenUIAccess: " + str(self.get_token_ui_access()) + "\n"
        t += "TokenLinkedToken: " + str(self.get_token_linked_token()) + "\n"
        t += "TokenLogonSid: " + str(self.get_token_logon_sid()) + "\n"
        t += "TokenElevation: " + str(self.get_token_elevation()) + "\n"
        if self.get_token_integrity_level():
            t += "TokenIntegrityLevel: " + str(self.get_token_integrity_level().get_fq_name()) + "\n"
        else:
            t += "TokenIntegrityLevel: [unknown]\n"
        t += "TokenMandatoryPolicy: " + str(self.get_token_mandatory_policy()) + "\n"
        t += "Token Resitrcted Sids:\n"
        for sid in self.get_token_restricted_sids():
            t += "\t" + sid.get_fq_name() + "\n"
        t += "IsTokenRestricted: " + str(self.get_token_restricted()) + "\n"
        t += "Token Groups:\n"
        for g, attr_a in self.get_token_groups():
            t += "\t%s: %s\n" % (g.get_fq_name(), "|".join(attr_a))
        t += "Token Privileges:\n"
        for p, a in self.get_token_privileges():
            t += "\t%-32s: %s\n" % (str(p), "|".join(a))
        t += "\nToken Security Descriptor:\n"
        if self.get_sd():
            t += self.get_sd().as_text()
        if self.get_token_linked_token():
            t += "\nDumping linked access token:\n"
            t += token(self.get_token_linked_token()).as_text_no_rec()
        t += '--- End Access Token ---\n'

        #print "token: as_text returning %s" % t
        return t

    def get_type(self):
        return 'token'
    
    def as_tab(self, dangerous_only=1):
        lines = []

        info = ["info", self.get_type()]
        if self.get_th_int():
            info.append(int(self.get_th_int()))
        else:
            info.append("")
        if self.get_token_owner():
            info.append(self.get_token_owner().get_fq_name())
        else:
            info.append("")
        if self.get_token_user():
            info.append(self.get_token_user().get_fq_name())
        else:
            info.append("")
        if self.get_token_primary_group():
            info.append(self.get_token_primary_group().get_fq_name())
        else:
            info.append("")
        info.append(self.get_token_type())
        info.append(self.get_token_impersonation_level())
        info.append(self.get_token_origin())
        info.append(self.get_token_source())
        info.append(self.get_token_restrictions())
        info.append(self.get_token_elevation_type())
        info.append(self.get_token_ui_access())
        info.append(self.get_token_linked_token())
        info.append(self.get_token_logon_sid())
        info.append(self.get_token_elevation())
        if self.get_token_integrity_level():
            info.append(self.get_token_integrity_level().get_fq_name())
        else:
            info.append("")
        info.append(self.get_token_mandatory_policy())
        info.append(self.get_token_restricted())

# Will cause an infinite loop
#        t =""
#        if self.get_token_linked_token():
#            t += token(self.get_token_linked_token()).as_tab()
#        info.append(t)

        lines.append(wpc.utils.tab_line(*info))
        for sid in self.get_token_restricted_sids():
            lines.append(wpc.utils.tab_line("info", "token_restricted_sid", self.get_th_int(), sid.get_fq_name()))
        for g, attr_a in self.get_token_groups():
            lines.append(wpc.utils.tab_line("info", "token_group", self.get_th_int(), g.get_fq_name(), "|".join(attr_a)))
        for p, a in self.get_token_privileges():
            lines.append(wpc.utils.tab_line("info", "token_privs", self.get_th_int(), p, "|".join(a)))
        if self.get_sd():
            lines.append(wpc.utils.tab_line("gotsd", self.get_type(), str(self.get_th_int()), "yes"))
            lines.append(wpc.utils.tab_line("owner", self.get_type(), str(self.get_th_int()), str(self.get_sd().get_owner().get_fq_name())))         
            if self.get_sd().has_dacl():
                lines.append(wpc.utils.tab_line("hasdacl", self.get_type(), str(self.get_th_int()), "yes"))
                if dangerous_only:
                    lines.extend(self.get_sd().dangerous_aces_as_tab("ace", self.get_type(), str(self.get_th_int())))
                else:
                    lines.extend(self.get_sd().aces_as_tab("ace", self.get_type(), str(self.get_th_int())))
            else:
                lines.append(wpc.utils.tab_line("hasdacl", self.get_type(), str(self.get_th_int()), "no"))
        else:
            lines.append(wpc.utils.tab_line("gotsd", self.get_type(), str(self.get_th_int()), "no"))
        #print lines
        return "\n".join(lines)