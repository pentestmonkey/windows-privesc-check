import wpc.conf
from zipfile import ZipFile
from lxml import etree as letree


class mspatchdb():
    def __init__(self, patchfile):
        self.patchfile = patchfile
        self.patchspreadsheet = []
        self.parse_spreadsheet(self.patchfile)

    def parse_spreadsheet(self, patchfile):
        myzip = ZipFile(patchfile, 'r')
        xml = myzip.read('xl/worksheets/sheet1.xml')
        xml = xml.replace("<x:", "<x")
        xml = xml.replace("</x:", "</x")
        xslt_root = letree.XML(wpc.conf.ms_spreadsheet_xslt_str)
        transform = letree.XSLT(xslt_root)
        datastring = str(transform(letree.XML(xml)))

        isheader = 1
        for rowstring in datastring.split("\n"):
            row = rowstring.split("|")
            if isheader:
                header = row
                isheader = 0
            else:
                count = 0
                newrow = {}
                for cell in row:
                    newrow[header[count]] = cell
                    count = count + 1
                self.patchspreadsheet.append(newrow)

    def is_applicable(self, msno, os):
        applicable = 0
        for row in self.patchspreadsheet:
            if row['Bulletin ID'] == msno and row['Affected Product'] == os:
                applicable = 1
                break
        return applicable

    def superseding_patch(self, msno, os):
        superseded_by = ""
        for row in self.patchspreadsheet:
            if row['Bulletin ID'] == msno and row['Affected Product'] == os:
                superseded_by = row['Superseded By']
                break
        return superseded_by

    def get_kbs_from_msno(self, msno, os):
        kbs = []
        for row in self.patchspreadsheet:
            if row['Bulletin ID'] == msno and row['Affected Product'] == os:
                kbs.append(row['Bulletin KB'])
                kbs.append(row['Component KB'])
                break
        return kbs

    def list_os_strings(self):
        oslist = {}
        for row in self.patchspreadsheet:
            if row['Affected Product'].find("Windows") > -1 and not row['Affected Product'].find("Media Player") > -1 and (row['Affected Product'].find("Windows 7") > -1 or row['Affected Product'].find("XP") > -1 or row['Affected Product'].find("Server 2008") > -1 or row['Affected Product'].find("Server 2003") > -1 or row['Affected Product'].find("Vista")) > -1:
                oslist[row['Affected Product']] = 1

        print "[+] Valid OS strings from xlsx file are:"
        for os in sorted(oslist.keys()):
            print "%s" % os

    def is_vali_os_string(self, os):
        for row in self.patchspreadsheet:
            if row['Affected Product'] == os:
                return 1
        return 0
