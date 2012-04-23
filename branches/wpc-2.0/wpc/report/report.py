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
        self.xsl_text = '''<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output method="text" indent="no"/>

<xsl:template match="report">
    <xsl:for-each select="issues/issue">
        <xsl:text>------------------------------------------------------------------
</xsl:text>
        <xsl:text>Title: </xsl:text><xsl:value-of select="normalize-space(title)" /><xsl:text>

</xsl:text>
        <xsl:for-each select="section">
            <xsl:text>[ </xsl:text><xsl:value-of select="@type" /><xsl:text> ]

</xsl:text>
                <xsl:call-template name="newline">
                    <xsl:with-param name="node" select="body"/>
                    <xsl:with-param name="clear">True</xsl:with-param>
                </xsl:call-template>
            <xsl:apply-templates select="details"/> 
        </xsl:for-each>
    </xsl:for-each>
</xsl:template>

<xsl:template match="details">
    <xsl:call-template name="newline">
        <xsl:with-param name="node" select="preamble"/>
        <xsl:with-param name="clear">True</xsl:with-param>
    </xsl:call-template>
    <xsl:for-each select="supporting_data/data">
        <xsl:call-template name="newline">
            <xsl:with-param name="preamble"><xsl:text>    </xsl:text></xsl:with-param>
            <xsl:with-param name="node" select="."/>
        </xsl:call-template>
    </xsl:for-each>
    <xsl:if test="supporting_data/*">
<xsl:text>
</xsl:text>
    </xsl:if>
</xsl:template>

<xsl:template name="newline">
<xsl:param name="node"/>
<xsl:param name="clear"/>
<xsl:param name="preamble"></xsl:param>
<xsl:if test="$node/text()">
       <xsl:value-of select="$preamble"/>
    <xsl:value-of select="normalize-space($node)"/>
    <xsl:text>
</xsl:text>
    <xsl:if test="$clear = 'True'">
        <xsl:text>
</xsl:text>
    </xsl:if>
</xsl:if>
</xsl:template>

</xsl:stylesheet>
        '''
        self.xsl_html = '''<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output method="xml" indent="yes" 
    doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"
    doctype-public="-//W3C//DTD XHTML 1.0 Transitional//EN" />

<xsl:template match="report">
    <html>
        <style type="text/css">
            body {color:black}
            td
            {
            vertical-align:top;
            }
            h1 {font-size: 300%; text-align:center}
            h2 {font-size: 200%; margin-top: 25px; margin-bottom: 0px; padding: 5px; background-color: #CCCCCC;}
            h3 {font-size: 150%; font-weight: normal; padding: 5px; background-color: #EEEEEE; margin-top: 10px;}
            #frontpage {height: 270px; background-color: #F3F3F3;}
            p.ex {color:rgb(0,0,255)}

            #customers
            {
            font-family:"Trebuchet MS", Arial, Helvetica, sans-serif;
            /* width:100%; */
            padding:10px 0px 0px 0px;
            border-collapse:collapse;
            }
            #customers td, #customers th 
            {
            font-size:1em;
            border:1px solid #989898;
            padding:3px 7px 2px 7px;
            }
            #customers th 
            {
            font-size:1.1em;
            text-align:left;
            padding-top:5px;
            padding-bottom:4px;
            background-color:#A7C942;
            color:#ffffff;
            }
            #customers tr.alt td 
            {
            color:#000000;
            background-color:#EAF2D3;
            }
        </style>
        
        <head>
            <div id="frontpage">
                <h1><p>Windows Privilege Escalation Report</p> <p>Audit of Host: </p><p><xsl:value-of select="scaninfo/hostname"/></p></h1>
            </div>
        </head>
        
        <body>
            <h2>Contents</h2>    
            <xsl:for-each select="issues/issue">
                <p><xsl:text disable-output-escaping="yes">&lt;a href=&quot;#</xsl:text><xsl:value-of select="normalize-space(title)"/><xsl:text disable-output-escaping="yes">&quot;&gt;</xsl:text><xsl:value-of select="normalize-space(title)"/><xsl:text disable-output-escaping="yes">&lt;/a&gt;</xsl:text></p>
            </xsl:for-each>
            
            <h2>Information about this Audit</h2>
            <p>This report was generated on <xsl:value-of select="scaninfo/datetime"/> by version <xsl:value-of select="scaninfo/version"/> of <a href="http://pentestmonkey.net/windows-privesc-check">windows-privesc-check</a>.</p>
            <p>The audit was run as the user <xsl:value-of select="scaninfo/user"/>.</p>
            <p>The following table provides information about this audit:</p>
            <table id="customers" border="1">
                <tr>
                    <td>Hostname</td>
                    <td><xsl:value-of select="scaninfo/hostname"/></td>
                </tr>
                
                <tr class="alt">
                    <td>Domain/Workgroup</td>
                    <td><xsl:value-of select="scaninfo/domain"/></td>
                </tr>

                <tr>
                    <td>Operating System</td>
                    <td><xsl:value-of select="scaninfo/os"/> (<xsl:value-of select="scaninfo/os_version"/>)</td>
                </tr>

                <tr class="alt">
                    <td>IP Addresses</td>
                    <td>
                        <ul>
                            <li><xsl:value-of select="scaninfo/ipaddress"/></li>
                        </ul>
                    </td>
                </tr>
            </table> 
            
            
            <h2>Escalation Vectors</h2>
            <xsl:for-each select="issues/issue">
                <hr/>
                <h3><xsl:text disable-output-escaping="yes">&lt;a name=&quot;</xsl:text><xsl:value-of select="normalize-space(title)"/><xsl:text disable-output-escaping="yes">&quot;&gt;</xsl:text><xsl:value-of select="normalize-space(title)"/><xsl:text disable-output-escaping="yes">&lt;/a&gt;</xsl:text></h3>
                <xsl:for-each select="section">
                    <table>
                        <tr>
                            <td>
                                <b><xsl:value-of select="@type" /></b>
                            </td>
                            <td>
                                <p><xsl:value-of select="normalize-space(body)"/></p>
                                <xsl:apply-templates select="details"/> 
                            </td>
                        </tr>
                        
                    </table>
                    
                </xsl:for-each>
            </xsl:for-each>
        </body>
    </html>
</xsl:template>

<xsl:template match="details">
    <p><xsl:value-of select="preamble"/></p>
    <xsl:if test="supporting_data/*">
        <ul>
        <xsl:for-each select="supporting_data/data">
            <li><xsl:value-of select="normalize-space(.)"/></li>
        </xsl:for-each>
        </ul>
    </xsl:if>
</xsl:template>

</xsl:stylesheet>
        '''
        
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
        # TODO: Top level version for XML schema
        # TODO: Raw data about object reported (files, service, etc.) 
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
        #if hasattr(sys, 'frozen'):
        #    datafile = os.path.join(os.environ['_MEIPASS2'], 'text.xsl')
        #elif __file__:
        #    datafile = os.path.join(os.path.dirname(__file__), '..', '..', 'xsl', 'text.xsl')
        #xslt_fh = open(datafile, 'r')
        #xslt_str  = xslt_fh.read() # TODO fixme
        xslt_str = self.xsl_text
        #xslt_fh.close()
        xslt_root = letree.XML(xslt_str)
        transform = letree.XSLT(xslt_root)
        return str(transform(letree.XML(self.as_xml_string())))

    # TODO duplicated lots of code from as_text
    def as_html(self):
        #if hasattr(sys, 'frozen'):
        #    datafile = os.path.join(os.environ['_MEIPASS2'], 'html.xsl')
        #elif __file__:
        #    datafile = os.path.join(os.path.dirname(__file__), '..', '..', 'xsl', 'html.xsl')
        #xslt_fh = open(datafile, 'r')
        #xslt_str  = xslt_fh.read() # TODO fixme
        xslt_str = self.xsl_html
        #xslt_fh.close()
        xslt_root = letree.XML(xslt_str)
        transform = letree.XSLT(xslt_root)
        return str(transform(letree.XML(self.as_xml_string())))
