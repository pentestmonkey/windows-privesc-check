import wpc.conf

import xml.etree.cElementTree as etree

class issue:
    def __init__(self, identifier):
        self.id = identifier
        self.supporting_data = {}

    def add_supporting_data(self, k, v):
        #print "ADD called"
        if not k in self.supporting_data.keys():
            self.supporting_data[k] = []
        self.supporting_data[k].append(v)

    def get_id(self):
        return self.id

    def render_supporting_data(self, data_name):
        # TODO: Also stash raw data in the report object.  XSLTs could then present differently.
        # expect an array of issue.fileAcl type for now
        d = etree.Element('supporting_data')
        if data_name == 'principals_with_service_perm':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                p = data[1]
                etree.SubElement(d, 'data').text = "    %s (%s) which runs as %s has permission granted for: %s\n" % (s.get_description(), s.get_name(), s.get_run_as(), p.get_fq_name())

        elif data_name == 'principals_with_service_ownership':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                p = data[1]
                etree.SubElement(d, 'data').text = "    %s (%s) which runs as %s is owned by %s\n" % (s.get_description(), s.get_name(), s.get_run_as(), p.get_fq_name())

        elif data_name == 'user_reg_keys':
            for data in self.get_supporting_data(data_name):
                u = data[0]
                r = data[1]
                value_name = data[2]
                value_data = data[3]
                u_name = "UNKNOWN"
                if u:
                    u_name = u.get_fq_name()
                etree.SubElement(d, 'data').text = "User: %s, Reg key: %s\%s, Value: %s" % (u_name, r.get_name(), value_name, value_data)

        elif data_name == 'reg_key_value':
            for data in self.get_supporting_data(data_name):
                r = data[0]
                value_name = data[1]
                value_data = data[2]
                etree.SubElement(d, 'data').text = "Reg key: %s\%s, Value: %s" % (r.get_name(), value_name, value_data)

        elif data_name == 'exploit_list':
            for data in self.get_supporting_data(data_name):
                e = data[0]
                etree.SubElement(d, 'data').text = "Missing patch %s: Metasploit exploit \"%s\" (%s)" % (e.get_msno(), e.get_title(), e.get_info("Metasploit Exploit Name"))

        elif data_name == 'dc_info':
            for data in self.get_supporting_data(data_name):
                dc_info = data[0]
                etree.SubElement(d, 'data').text = "Domain Name: %s" % (dc_info["DomainName"])

        elif data_name == 'writable_dirs':
            for data in self.get_supporting_data(data_name):
                f = data[0]
                a = data[1]
                etree.SubElement(d, 'data').text = "    File %s has weak permissions: %s\n" % (f.get_name(), a.as_text())

        elif data_name == 'writable_progs':
            for data in self.get_supporting_data(data_name):
                f = data[0]
                a = data[1]
                etree.SubElement(d, 'data').text = "    File %s has weak permissions: %s\n" % (f.get_name(), a.as_text())

        elif data_name == 'writable_files':
            for data in self.get_supporting_data(data_name):
                f = data[0]
                a = data[1]
                etree.SubElement(d, 'data').text = "    File %s has weak permissions: %s\n" % (f.get_name(), a.as_text())

        elif data_name == 'service_exe_write_perms':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                f = data[1]
                etree.SubElement(d, 'data').text = " %s (%s) runs the following program as %s:\n" % (s.get_description(), s.get_name(), s.get_run_as())
                etree.SubElement(d, 'data').text = "  %s\n" % (f.as_text())

        elif data_name == 'service_exe_owner':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                etree.SubElement(d, 'data').text = " %s (%s) runs the following program '%s' as %s.  Program is owned by untrusted user %s:\n" % (s.get_description(), s.get_name(), s.get_exe_file().get_name(), s.get_run_as(), s.get_exe_file().get_sd().get_owner().get_fq_name())

        elif data_name == 'file_untrusted_ownership':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                etree.SubElement(d, 'data').text = " %s (%s) runs %s as %s.  Program owned by %s\n" % (s.get_description(), s.get_name(), s.get_exe_file().get_name(), s.get_run_as(), s.get_exe_file().get_sd().get_owner().get_fq_name())

        elif data_name == 'service_exe_parent_dir_untrusted_ownership':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                f = data[1]
                etree.SubElement(d, 'data').text = " %s (%s) runs %s as %s.  Parent directory %s is owned by %s\n" % (s.get_description(), s.get_name(), s.get_exe_file().get_name(), s.get_run_as(), f.get_name(), f.get_sd().get_owner().get_fq_name())

        elif data_name == 'service_exe_file_parent_write_perms' or data_name == 'service_exe_parent_grandparent_write_perms':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                f = data[1]
                fp = data[2]
                etree.SubElement(d, 'data').text = " %s (%s) runs %s as %s" % (s.get_description(), s.get_name(), s.get_exe_file().get_name(), s.get_run_as())
                etree.SubElement(d, 'data').text = "  %s\n" % (f.as_text())
                etree.SubElement(d, 'data').text = "  %s\n" % (fp.as_text())

        elif data_name == 'service_exe_parent_dir_perms':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                f = data[1]
                etree.SubElement(d, 'data').text = " %s (%s) runs %s as %s\n" % (s.get_description(), s.get_name(), s.get_exe_file().get_name(), s.get_run_as())
                etree.SubElement(d, 'data').text = "  %s\n" % (f.as_text())

        elif data_name == 'service_exe_regkey_untrusted_ownership':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                r = data[1]
                etree.SubElement(d, 'data').text = " %s (%s) uses registry key %s, owned by %s" % (s.get_description(), s.get_name(), r.get_name(), r.get_sd().get_owner().get_fq_name())        

        elif data_name == 'regkey_untrusted_ownership':
            for data in self.get_supporting_data(data_name):
                r = data[0]
                etree.SubElement(d, 'data').text = "Registry key %s is owned by %s" % (r.get_name(), r.get_sd().get_owner().get_fq_name())        

        elif data_name == 'scheduled_task_exe_perms':
            for data in self.get_supporting_data(data_name):
                t = data[0]
                f = data[1]
                a = data[2]
                etree.SubElement(d, 'data').text = " Task %s runs '%s' which has weak permissions:\n" % (t, f.get_name())
                etree.SubElement(d, 'data').text = "  %s\n" % (a.as_text())

        elif data_name == 'service_reg_perms':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                a = data[1]
                etree.SubElement(d, 'data').text = " %s (%s) uses registry key %s:\n" % (s.get_description(), s.get_name(), a.get_name())
                etree.SubElement(d, 'data').text = "  %s\n" % (a.as_text())

        elif data_name == 'regkey_value_data_perms':
            for data in self.get_supporting_data(data_name):
                r = data[0]
                v = data[1]
                regdata = data[2]
                a = data[3]
                etree.SubElement(d, 'data').text = "Registry value %s\%s has data '%s' and permissions:\n" % (wpc.utils.to_printable(r.get_name()), wpc.utils.to_printable(v), wpc.utils.to_printable(regdata))
                etree.SubElement(d, 'data').text = "  %s\n" % (a.as_text())

        elif data_name == 'regkey_perms':
            for data in self.get_supporting_data(data_name):
                r = data[0]
                a = data[1]
                etree.SubElement(d, 'data').text = "Registry value %s has permissions:\n" % (r.get_name())        
                etree.SubElement(d, 'data').text = "  %s\n" % (a.as_text())

        elif data_name == 'service_info':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                etree.SubElement(d, 'data').text = " %s (%s) runs as %s and has path: %s:\n" % (s.get_description(), s.get_name(), s.get_run_as(), s.get_exe_path())        

        elif data_name == 'service_domain_user':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                etree.SubElement(d, 'data').text = " %s (%s) runs as %s\n" % (s.get_description(), s.get_name(), s.get_run_as())        

        elif data_name == 'service_no_exe':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                etree.SubElement(d, 'data').text = " %s (%s) tries to run '%s' as %s\n" % (s.get_description(), s.get_name(), s.get_exe_path(), s.get_run_as())        

        elif data_name == 'service_dll':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                r = data[1]
                f = data[2]
                etree.SubElement(d, 'data').text = " Service %s (%s) runs as %s: Regkey %s references %s which has weak file permissions (TODO how so?)\n" % (s.get_description(), s.get_name(), s.get_run_as(), r.get_name(), f.get_name())

        elif data_name == 'regkey_ref_replacable_file':
            for data in self.get_supporting_data(data_name):
                keytype = data[0]
                name = data[1]
                clsid = data[2]
                f = data[3]
                r = data[4]
                etree.SubElement(d, 'data').text = " %s \"%s\" uses CLSID %s which references the following file with weak permissions: %s [defined in %s] - TODO how are perms weak?\n" % (type, name, clsid, f.get_name(), r.get_name())

        elif data_name == 'regkey_ref_file':
            for data in self.get_supporting_data(data_name):
                r = data[0]
                v = data[1]
                f = data[2]
                etree.SubElement(d, 'data').text = " %s references %s which has weak permissions.  TODO weak how?\n" % (r.get_name() + "\\" + v, f.get_name())

        elif data_name == 'sectool_services':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                etree.SubElement(d, 'data').text = " %s (%s) runs '%s' as %s\n" % (s.get_description(), s.get_name(), s.get_exe_path(), s.get_run_as()) 

        elif data_name == 'sectool_files':
            for data in self.get_supporting_data(data_name):
                f = data[0]
                etree.SubElement(d, 'data').text = " %s\n" % (f.get_name())

        elif data_name == 'file_read':
            for data in self.get_supporting_data(data_name):
                f = data[0]
                u = data[1]
                etree.SubElement(d, 'data').text = " %s can be read by %s\n" % (f.get_name(), u.get_fq_name())

        elif data_name == 'process_exe':
            for data in self.get_supporting_data(data_name):
                p = data[0]
                etree.SubElement(d, 'data').text = " Process ID %s (%s) as weak permissions.  TODO: Weak how?\n" % (p.get_pid(), p.get_exe().get_name())

        elif data_name == 'user_powerful_priv':
            for data in self.get_supporting_data(data_name):
                u = data[0]
                etree.SubElement(d, 'data').text = " %s\n" % (u.get_fq_name())

        elif data_name == 'username':
            for data in self.get_supporting_data(data_name):
                u = data[0]
                etree.SubElement(d, 'data').text = " %s\n" % (u.get_fq_name())

        elif data_name == 'password_age':
            for data in self.get_supporting_data(data_name):
                u = data[0]
                etree.SubElement(d, 'data').text = " %s: %s days\n" % (u.get_fq_name(), u.get_password_age()/(3600*24))

        elif data_name == 'group_powerful_priv':
            for data in self.get_supporting_data(data_name):
                u = data[0]
                etree.SubElement(d, 'data').text = " %s\n" % (u.get_fq_name())

        elif data_name == 'share_perms':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                u = data[1]
                etree.SubElement(d, 'data').text = " Share %s (%s) is accessible by %s\n" % (s.get_name(), s.get_description(), u.get_fq_name())

        elif data_name == 'writable_eventlog_dll' or data_name == 'writable_eventlog_file':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                f = data[1]
                etree.SubElement(d, 'data').text = " Registry key %s refers to replaceable file %s TODO print file perms?\n" % (s.get_name(), f.get_name())

        elif data_name == 'drive_and_fs_list':
            for data in self.get_supporting_data(data_name):
                drive = data[0]
                etree.SubElement(d, 'data').text = " Drive %s has %s filesystem\n" % (drive.get_name(), drive.get_fs())

        elif data_name == 'dir_add_file':
            for data in self.get_supporting_data(data_name):
                drive = data[0]
                a = data[1]
                etree.SubElement(d, 'data').text = " Drive %s allows %s to add files\n" % (drive.get_name(), a.get_principal().get_fq_name())

        elif data_name == 'dir_add_dir':
            for data in self.get_supporting_data(data_name):
                drive = data[0]
                a = data[1]
                etree.SubElement(d, 'data').text = " Drive %s allows %s to add directories\n" % (drive.get_name(), a.get_principal().get_fq_name())

        elif data_name == 'process_dll':
            for data in self.get_supporting_data(data_name):
                p = data[0]
                dll = data[1]
                if p.get_exe():
                    exe = p.get_exe().get_name()
                else:
                    exe = "[unknown]"
                etree.SubElement(d, 'data').text = " Process ID %s (%s) uses DLL %s.  DLL has weak permissions.  TODO: Weak how?\n" % (p.get_pid(), p.get_exe().get_name(), dll.get_name())

        elif data_name == 'process_perms':
            for data in self.get_supporting_data(data_name):
                p = data[0]
                perms = data[1]
                if p.get_exe():
                    exe = p.get_exe().get_name()
                else:
                    exe = "[unknown]"
                etree.SubElement(d, 'data').text = " Process ID %s (%s) has weak process-level permissions: %s\n" % (p.get_pid(), exe, perms.as_text())

        elif data_name == 'thread_perms':
            for data in self.get_supporting_data(data_name):
                t = data[0]
                perms = data[1]
                p = t.get_parent_process()
                if p and p.get_exe():
                    exe = p.get_exe().get_name()
                else:
                    exe = "[unknown]"
                etree.SubElement(d, 'data').text = " Tread ID %s of Process ID %s (%s) has weak thread-level permissions: %s\n" % (t.get_tid(), p.get_pid(), exe, perms.as_text())

        elif data_name == 'token_perms':
            for data in self.get_supporting_data(data_name):
                t = data[0]
                p = data[1]
                perms = data[2]
                if p and p.get_exe():
                    exe = p.get_exe().get_name()
                else:
                    exe = "[unknown]"
                etree.SubElement(d, 'data').text = " An Access Token in Process ID %s (%s) or one of its threads has weak token-level permissions: %s\n" % (p.get_pid(), exe, perms.as_text())

        elif data_name == 'writeable_dirs' or data_name == 'files_write_perms':
            for o in self.get_supporting_data(data_name):
                etree.SubElement(d, 'data').text = o.as_text() + "\n"
            #print "RETURNING: " + d
        return d

    def get_supporting_data(self, data_name):
        #print "data_name: " + data_name
        #print "keys: " + " ".join(self.supporting_data.keys())
        if data_name in self.supporting_data.keys():
            return self.supporting_data[data_name]
        else:
            return None

    def get_rendered_supporting_data(self, section):
        d = etree.Element('details')
        for data_name in wpc.conf.issue_template[self.get_id()]['supporting_data'].keys():
            if wpc.conf.issue_template[self.get_id()]['supporting_data'][data_name]['section'] == section:
                if self.get_supporting_data(data_name):
                    etree.SubElement(d, 'preamble').text = wpc.conf.issue_template[self.get_id()]['supporting_data'][data_name]['preamble'] + "\n\n"
                    d.append(self.render_supporting_data(data_name))
        return d

    def as_xml(self):
        r = etree.Element('issue')
        etree.SubElement(r, 'title').text = wpc.conf.issue_template[self.get_id()]['title']
        s = etree.SubElement(r, 'section', type = 'description')
        etree.SubElement(s, 'body').text = wpc.conf.issue_template[self.get_id()]['description']
        s.append(self.get_rendered_supporting_data('description'))
        s = etree.SubElement(r, 'section', type = 'recommendation')
        etree.SubElement(s, 'body').text = wpc.conf.issue_template[self.get_id()]['recommendation']
        s.append(self.get_rendered_supporting_data('recommendation'))
        return r

