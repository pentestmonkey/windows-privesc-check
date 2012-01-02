import wpc.conf


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
        # expect an array of issue.fileAcl type for now
        d = ''
        if data_name == 'principals_with_service_perm':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                p = data[1]
                d += "    %s (%s) which runs as %s has permission granted for: %s\n" % (s.get_description(), s.get_name(), s.get_run_as(), p.get_fq_name())

        elif data_name == 'principals_with_service_ownership':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                p = data[1]
                d += "    %s (%s) which runs as %s is owned by %s\n" % (s.get_description(), s.get_name(), s.get_run_as(), p.get_fq_name())

        elif data_name == 'service_exe_write_perms':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                f = data[1]
                d += " %s (%s) runs the following program as %s:\n" % (s.get_description(), s.get_name(), s.get_run_as())
                d += "  %s\n" % (f.as_text())

        elif data_name == 'file_untrusted_ownership':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                d += " %s (%s) runs %s as %s.  Program owned by %s\n" % (s.get_description(), s.get_name(), s.get_exe_file().get_name(), s.get_run_as(), s.get_exe_file().get_sd().get_owner().get_fq_name())

        elif data_name == 'service_exe_parent_dir_untrusted_ownership':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                f = data[1]
                d += " %s (%s) runs %s as %s.  Parent directory %s is owned by %s\n" % (s.get_description(), s.get_name(), s.get_exe_file().get_name(), s.get_run_as(), f.get_name(), f.get_sd().get_owner().get_fq_name())

        elif data_name == 'service_exe_file_parent_write_perms':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                f = data[1]
                fp = data[2]
                d += " %s (%s) runs %s as %s" % (s.get_description(), s.get_name(), s.get_exe_file().get_name(), s.get_run_as())
                d += "  %s\n" % (f.as_text())
                d += "  %s\n" % (fp.as_text())

        elif data_name == 'service_exe_parent_dir_perms':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                f = data[1]
                d += " %s (%s) runs %s as %s\n" % (s.get_description(), s.get_name(), s.get_exe_file().get_name(), s.get_run_as())
                d += "  %s\n" % (f.as_text())

        elif data_name == 'service_exe_parent_grandparent_write_perms':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                f = data[1]
                fp = data[2]
                d += " %s (%s) runs %s as %s" % (s.get_description(), s.get_name(), s.get_exe_file().get_name(), s.get_run_as())
                d += "  %s\n" % (f.as_text())
                d += "  %s\n" % (fp.as_text())

        elif data_name == 'service_exe_regkey_untrusted_ownership':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                r = data[1]
                d += " %s (%s) uses registry key %s, owned by %s" % (s.get_description(), s.get_name(), r.get_name(), r.get_sd().get_owner().get_fq_name())        

        elif data_name == 'regkey_untrusted_ownership':
            for data in self.get_supporting_data(data_name):
                r = data[0]
                d += "Registry key %s is owned by %s" % (r.get_name(), r.get_sd().get_owner().get_fq_name())        

        elif data_name == 'service_reg_perms':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                a = data[1]
                d += " %s (%s) uses registry key %s:\n" % (s.get_description(), s.get_name(), a.get_name())        
                d += "  %s\n" % (a.as_text())

        elif data_name == 'regkey_perms':
            for data in self.get_supporting_data(data_name):
                r = data[0]
                a = data[1]
                d += "Registry key %s has permissions:\n" % (r.get_name())        
                d += "  %s\n" % (a.as_text())

        elif data_name == 'service_info':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                d += " %s (%s) runs as %s and has path: %s:\n" % (s.get_description(), s.get_name(), s.get_run_as(), s.get_exe_path())        

        elif data_name == 'service_domain_user':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                d += " %s (%s) runs as %s\n" % (s.get_description(), s.get_name(), s.get_run_as())        

        elif data_name == 'service_no_exe':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                d += " %s (%s) tries to run '%s' as %s\n" % (s.get_description(), s.get_name(), s.get_exe_path(), s.get_run_as())        

        elif data_name == 'service_dll':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                r = data[1]
                f = data[2]
                d += " Service %s (%s) runs as %s: Regkey %s references %s which has weak file permissions (TODO how so?)\n" % (s.get_description(), s.get_name(), s.get_run_as(), r.get_name(), f.get_name())

        elif data_name == 'regkey_ref_replacable_file':
            for data in self.get_supporting_data(data_name):
                type = data[0]
                name = data[1]
                clsid = data[2]
                f = data[3]
                r = data[4]
                d += " %s \"%s\" uses CLSID %s which references the following file with weak permissions: %s [defined in %s] - TODO how are perms weak?\n" % (type, name, clsid, f.get_name(), r.get_name())

        elif data_name == 'regkey_ref_file':
            for data in self.get_supporting_data(data_name):
                r = data[0]
                v = data[1]
                f = data[2]
                d += " %s references %s which has weak permissions.  TODO weak how?\n" % (r.get_name() + "\\" + v, f.get_name())

        elif data_name == 'sectool_services':
            for data in self.get_supporting_data(data_name):
                s = data[0]
                d += " %s (%s) runs '%s' as %s\n" % (s.get_description(), s.get_name(), s.get_exe_path(), s.get_run_as()) 

        elif data_name == 'sectool_files':
            for data in self.get_supporting_data(data_name):
                f = data[0]
                d += " %s\n" % (f.get_name())

        elif data_name == 'writeable_dirs' or data_name == 'files_write_perms':
            for o in self.get_supporting_data(data_name):
                d += o.as_text() + "\n"
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
        d = ''
        for data_name in wpc.conf.issue_template[self.get_id()]['supporting_data'].keys():
            if wpc.conf.issue_template[self.get_id()]['supporting_data'][data_name]['section'] == section:
                if self.get_supporting_data(data_name):
                    d += wpc.conf.issue_template[self.get_id()]['supporting_data'][data_name]['preamble'] + "\n\n"    
                    d += self.render_supporting_data(data_name)
        return d

    def as_text(self):
        t = '------------------------------------------------------------------' + "\n"
        t += "Title: %s" % wpc.conf.issue_template[self.get_id()]['title'] + "\n\n"
        t += "[ Description ]\n\n%s\n\n" % wpc.conf.issue_template[self.get_id()]['description']
        t += self.get_rendered_supporting_data('description') + "\n"
        t += "[ Recommendation ]\n\n%s\n\n" % wpc.conf.issue_template[self.get_id()]['recommendation']
        t += self.get_rendered_supporting_data('recommendation') + "\n"
        return t
