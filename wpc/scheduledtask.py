import wpc.utils

class scheduledtask():
    def __init__(self, name, root):
            self.root = root
            self.name = name
            self.author = None
            self.description = None
            self.uri = None
            self.source = None
            self.date = None
            self.sd_text = None
            self.enabled = None
            self.command = None
            self.command_args = None
            self.comhandler = None
            self.runas = None
            self.comhandler_data = None
            self.action_context = None
            self.command_path = None
            self.command_set = 0
            self.principal_groupid = None
            self.principal_userid = None
            self.principal_runlevel = None
            self.principal_id = None
            self.exec_command = "<none>"
            self.exec_args = "<none>"
            try: 
                self.exec_command = root.Actions.Exec.Command
                self.exec_args = root.Actions.Exec.Arguments
            except:
                pass
            
            # source, author and description often refer to DLLs
            # run as: <task\Actions Context="LocalSystem">
            # triggers (0 or more - each of which can be enabled or not)
            # principals - not sure if this is same as runas
            
            
    def get_name(self):
        return self.name
    
    def get_action_context(self):
        if not self.action_context:
            try:
                self.action_context = self.root.Actions.attrib["Context"]
            except:
                self.action_context = "<not set>"
        return self.action_context
    
    def get_comhandler(self):
        if not self.comhandler:
            try:
                self.comhandler = self.root.Actions.ComHandler.ClassId
            except:
                self.comhandler = "<not set>"
        return self.comhandler
    
    def get_comhandler_data(self):
        if not self.comhandler_data:
            try:
                self.comhandler_data = self.root.Actions.ComHandler.Data
            except:
                self.comhandler_data = "<not set>"
        return self.comhandler_data
    
    def get_command(self):
        if not self.command:
            try:
                self.command = self.root.Actions.Exec.Command
                self.command_set = 1
            except:
                self.command = "<not set>"
        return self.command

    def get_command_path(self):
        if not self.command_path:
            try:
                self.command_path = wpc.utils.dequote(wpc.utils.env_expand(self.get_command()))
                #self.command_path = wpc.utils.env_expand(self.get_command())
            except:
                self.command_path = "<not set>"
        if not self.command_set:
            return None
        return self.command_path
    
    def get_command_args(self):
        if not self.command_args:
            try:
                self.command_args = self.root.Actions.Exec.Arguments
            except:
                self.command_args = "<not set>"
        return self.command_args
    
    def get_author(self):
        if not self.author:
            try:
                self.author = self.root.RegistrationInfo.Author
            except:
                self.author = "<not set>"
        return self.author

    def get_principal_groupid(self):
        if not self.principal_groupid:
            try:
                self.principal_groupid = self.root.Principals.Principal.GroupId
            except:
                self.principal_groupid = "<not set>"
        return self.principal_groupid
    
    def get_principal_userid(self):
        if not self.principal_userid:
            try:
                self.principal_userid = self.root.Principals.Principal.UserId
            except:
                self.principal_userid = "<not set>"
        return self.principal_userid
    
    def get_principal_runlevel(self):
        if not self.principal_runlevel:
            try:
                self.principal_runlevel = self.root.Principals.Principal.RunLevel
            except:
                self.principal_runlevel = "<not set>"
        return self.principal_runlevel
    
    def get_principal_id(self):
        if not self.principal_id:
            try:
                self.principal_id = self.root.Principals.Principal.attrib["id"]
            except:
                self.principal_id = "<not set>"
        return self.principal_id
    
    def get_enabled(self):
        if not self.enabled:
            try:
                self.enabled = self.root.Settings.Enabled
            except:
                self.enabled = "<not set>"
        return self.enabled
    
    def get_date(self):
        if not self.date:
            try:
                self.date = self.root.RegistrationInfo.Date
            except:
                self.date = "<not set>"
        return self.date
    
    def get_sd_text(self):
        if not self.sd_text:
            try:
                self.sd_text = self.root.RegistrationInfo.SecurityDescriptor
            except:
                self.sd_text = "<not set>"
        return self.sd_text
    
    def get_source(self):
        if not self.source:
            try:
                self.source = self.root.RegistrationInfo.Source
            except:
                self.source = "<not set>"
        return self.source
    
    def get_description(self):
        if not self.description:
            try:
                self.description = self.root.RegistrationInfo.Description
            except:
                self.description = "<not set>"
        return self.description
    
    def get_uri(self):
        if not self.uri:
            try:
                self.uri = self.root.RegistrationInfo.URI
            except:
                self.uri = "<not set>"
        return self.uri
    
    
    def as_tab(self):
        fields = ["info", "scheduledtask"]
        fields.append(self.get_name())
        fields.append(self.get_uri())
        fields.append(self.get_source())
        fields.append(self.get_author())
        fields.append(self.get_description())
        fields.append(self.get_date())
        fields.append(self.get_enabled())
        fields.append(self.get_sd_text())
        fields.append(self.get_action_context())
        fields.append(self.get_principal_groupid())
        fields.append(self.get_principal_userid())
        fields.append(self.get_principal_id())
        fields.append(self.get_principal_id())
        fields.append(self.get_comhandler())
        fields.append(self.get_comhandler_data())
        fields.append(self.get_command())
        fields.append(self.get_command_path())
        fields.append(self.get_command_args())
        return wpc.utils.tab_line(*fields)
        
    def as_text(self):
        t = ""
        t += "----------------------\n"
        t += "Name: %s\n" % self.get_name()
        t += "URI: %s\n" % self.get_uri()
        t += "Source: %s\n" % self.get_source()
        t += "Author: %s\n" % self.get_author()
        t += "Description: %s\n" % self.get_description()
        t += "Date: %s\n" % self.get_date()
        t += "Enabled: %s\n" % self.get_enabled()
        t += "SD: %s\n" % self.get_sd_text()
        t += "action_context: %s\n" % self.get_action_context()
        t += "principal_groupid: %s\n" % self.get_principal_groupid()
        t += "principal_userid: %s\n" % self.get_principal_userid()
        t += "principal_runlevel: %s\n" % self.get_principal_id()
        t += "principal_id: %s\n" % self.get_principal_id()
        t += "comhandler: %s\n" % self.get_comhandler()
        t += "comhandler_data: %s\n" % self.get_comhandler_data()
        t += "command: %s\n" % self.get_command()
        t += "command_path: %s\n" % self.get_command_path()
        t += "command_args: %s\n" % self.get_command_args()
        return t
    
