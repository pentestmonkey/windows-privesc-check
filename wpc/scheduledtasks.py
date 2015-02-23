from wpc.scheduledtask import scheduledtask
import re
import subprocess
from lxml import objectify
import os

class scheduledtasks():
    def __init__(self):
        self.tasks = []
        
    def get_all_tasks(self, **kwargs):
        try:
            content = subprocess.check_output("schtasks /query /xml", stderr = open(os.devnull, 'w'))
        except:
            print "[E] Can't run schtasks.  Doesn't work < Vista.  Skipping."
            return 0
        
        chunks = content.split("<!-- ")
        
        count = 0
        for chunk in chunks:
            count = count + 1
            if count == 1:
                continue # skip first chunk
        
            m = re.search("(.*) -->(.*)", chunk, re.MULTILINE | re.DOTALL)
            name = m.group(1)
            xml_string = m.group(2).lstrip()
            xml_string = xml_string.replace("UTF-16", "UTF-8")
            xml_string = xml_string.replace("</Tasks>", "")
            root = objectify.fromstring(xml_string)
            self.tasks.append(scheduledtask(name, root))
        
        return self.tasks
            

        