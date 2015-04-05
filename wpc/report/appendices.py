import xml.etree.cElementTree as etree
from wpc.report.appendix import appendix

class appendices:
    def __init__(self):
        self.appendices = []

    def add_appendix(self, a):
        self.appendices.append(a)

    def as_xml_string(self):
        return etree.tostring(self.as_xml())

    def as_xml(self):
        r = etree.Element('appendices')
        for i in self.appendices:
            r.append(i.as_xml())
        return r
