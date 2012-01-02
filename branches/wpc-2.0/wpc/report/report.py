from wpc.report.issues import issues
import xml.etree.cElementTree as etree
from lxml import etree as letree

# A list of issues with some information about the scan
class report():
    def __init__(self):
        self.info = {}
        self.issues = issues()

    def get_issues(self):
        return self.issues

    def get_info_item(self, k):  # key
        if k in self.info.keys():
            #return (self.info[k]['type'], self.info[k]['value'])
            return self.info[k]['value']
        return None

    def add_info_item(self, k, v):  # key, value
        self.info[k] = {}
        self.info[k]['value'] = v
        #self.info[k]['type'] = t

    def get_info(self):
        return self.info

    def as_xml(self):
        r = etree.Element('report')
        s = etree.Element('scaninfo')
        for k in self.get_info().keys():
            i = etree.Element(k)
            i.text = self.get_info_item(k)
            s.append(i)
        r.append(s)
        r.append(self.get_issues().as_xml())
        return r

    def as_xml_string(self):
        return etree.tostring(self.as_xml())

    def as_text(self):
        xslt_fh = open('xsl/text.xsl', 'r')  # TODO need to be able to run from other dirs too!
        xslt_str  = xslt_fh.read()
        xslt_fh.close()
        xslt_root = letree.XML(xslt_str)
        transform = letree.XSLT(xslt_root)
        return str(transform(letree.XML(self.as_xml_string())))

    def as_html(self):
        xslt_fh = open('xsl/html.xsl', 'r')  # TODO need to be able to run from other dirs too!
        xslt_str  = xslt_fh.read()
        xslt_fh.close()
        xslt_root = letree.XML(xslt_str)
        transform = letree.XSLT(xslt_root)
        return str(transform(letree.XML(self.as_xml_string())))

#        r = etree.Element('issue')
#        etree.SubElement(r, 'title').text = wpc.conf.issue_template[self.get_id()]['title']
#        s = etree.SubElement(r, 'section', type = 'description')