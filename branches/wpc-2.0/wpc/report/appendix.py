import wpc.conf
import xml.etree.cElementTree as etree

class appendix:
    def __init__(self, title):
        self.title = title
        self.preamble = None
        self.table = []
        self.table_name = None
        self.table_style = None

    def add_table_row(self, cells):
        self.table.append(map(lambda x: wpc.utils.to_printable(x), cells))

    def get_title(self):
        return self.title

    def get_preamble(self):
        return self.preamble

    def set_preamble(self, preamble):
        self.preamble = preamble

    def get_table_name(self):
        return self.table_name

    def get_table_style(self):
        return self.table_style

    def set_title(self, title):
        self.title = title

    def set_table_name(self, table_name):
        self.table_name = table_name

    def set_table_style(self, table_name):
        self.table_style = table_name

    def get_table(self):
        return self.table

    def as_xml(self):
        appendix = etree.Element('appendix', title = self.title)
        preamble = etree.Element('preamble')
        preamble.text = self.preamble
        appendix.append(preamble)
        args = {}
        if self.table_name:
            args['name'] = self.table_name
        if self.table_style:
            args['style'] = self.table_style
        table = etree.Element('table', *args)
        for r in self.get_table():
            row = etree.Element('row')
            for c in r:
                cell = etree.Element('cell')
                cell.text = c
                row.append(cell)
            table.append(row)
        appendix.append(table)
        return appendix

