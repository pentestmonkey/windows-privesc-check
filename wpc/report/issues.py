from wpc.report.issue import issue
import xml.etree.cElementTree as etree
from lxml import etree as letree


# TODO should this class contain info about the scan?  or define a new class called report?
# Version of script
# Date, time of audit
# Who the audit ran as (username, groups, privs)
# ...
class issues:
    def __init__(self):
        self.issues = []

    def get_by_id(self, identifier):
        # search for issue
        for i in self.issues:
            if i.get_id() == identifier:
                return i

        # create new issue
        i = issue(identifier)
        self.add_issue(i)
        return i

    def add_issue(self, i):
        self.issues.append(i)

    def add_supporting_data(self, identifier, k, v):
        self.get_by_id(identifier).add_supporting_data(k, v)

    def get_all(self):
        return self.issues

    def as_xml_string(self):
        return etree.tostring(self.as_xml())

    def as_xml(self):
        r = etree.Element('issues')
        for i in self.get_all():
            r.append(i.as_xml())
        return r

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
