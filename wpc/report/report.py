from wpc.report.issues import issues
import xml.etree.cElementTree as etree
from lxml import etree as letree
import os.path
import sys


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
        if hasattr(sys, 'frozen'):
            datafile = os.path.join(os.environ['_MEIPASS2'], 'text.xsl')
        elif __file__:
            datafile = os.path.join(os.path.dirname(__file__), '..', '..', 'xsl', 'text.xsl')
        xslt_fh = open(datafile, 'r')
        xslt_str  = xslt_fh.read()
        xslt_fh.close()
        xslt_root = letree.XML(xslt_str)
        transform = letree.XSLT(xslt_root)
        return str(transform(letree.XML(self.as_xml_string())))

    # TODO duplicated lots of code from as_text
    def as_html(self):
        if hasattr(sys, 'frozen'):
            datafile = os.path.join(os.environ['_MEIPASS2'], 'html.xsl')
        elif __file__:
            datafile = os.path.join(os.path.dirname(__file__), '..', '..', 'xsl', 'html.xsl')
        xslt_fh = open(datafile, 'r')
        xslt_str  = xslt_fh.read()
        xslt_fh.close()
        xslt_root = letree.XML(xslt_str)
        transform = letree.XSLT(xslt_root)
        return str(transform(letree.XML(self.as_xml_string())))
