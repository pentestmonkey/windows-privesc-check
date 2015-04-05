from wpc.report.issues import issues
from wpc.report.appendices import appendices
import xml.etree.cElementTree as etree
from lxml import etree as letree
import os.path
import sys
import wpc.conf

# A list of issues with some information about the scan
class report():
    def __init__(self):
        self.info = {}
        self.issues = issues()
        self.appendices = appendices()
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
            td {
                vertical-align:top;
            }
            #ratinginfo {
                border-collapse:collapse;
            }
            #ratinginfo td {
                border: 1px solid black;
            }
            #ratinginfo td.rating0 {
                color:#000000;
                background-color:#FFFFFF;
            }
            #ratinginfo td.rating1 {
                color:#000000;
                background-color:#FFFFBF;
            }
            #ratinginfo td.rating2 {
                color:#000000;
                background-color:#FFFF00;
            }
            #ratinginfo td.rating3 {
                color:#000000;
                background-color:#FF7F00;
            }
            #ratinginfo td.rating4 {
                color:#000000;
                background-color:#FF3F00;
            }
            #ratinginfo td.rating5 {
                color:#000000;
                background-color:#FF0000;
            }
            h1 {font-size: 300%; text-align:center}
            h2 {font-size: 200%; margin-top: 25px; margin-bottom: 0px; padding: 5px; background-color: #CCCCCC;}
            h3 {font-size: 150%; font-weight: normal; padding: 5px; background-color: #EEEEEE; margin-top: 10px;}
            #frontpage {height: 270px; background-color: #F3F3F3;}
            p.ex {color:rgb(0,0,255)}

            #auditinfo {            
                font-family:"Trebuchet MS", Arial, Helvetica, sans-serif;
                /* width:100%; */
                padding:10px 0px 0px 0px;
                border-collapse:collapse;
            }
            #auditinfo td, #auditinfo th 
            {
            font-size:1em;
            border:1px solid #989898;
            padding:3px 7px 2px 7px;
            }
            #auditinfo th 
            {
            font-size:1.1em;
            text-align:left;
            padding-top:5px;
            padding-bottom:4px;
            background-color:#A7C942;
            color:#ffffff;
            }
            #auditinfo tr.alt td 
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
            <p></p>
                <table id="ratinginfo">
                    <tr>
                        <td><b>Impact</b></td>
                        <td><b>Ease of exploitation</b></td>
                        <td><b>Confidence</b></td>
                        <td><b>Title</b></td>
                    </tr>
            <xsl:for-each select="issues/issue">
                    <tr>
                        <xsl:text disable-output-escaping="yes">&lt;td class=&quot;rating</xsl:text><xsl:value-of select="normalize-space(impact_number)"/><xsl:text disable-output-escaping="yes">&quot;&gt;</xsl:text><xsl:value-of select="normalize-space(impact_text)"/><xsl:text disable-output-escaping="yes">&lt;/td&gt;</xsl:text>
                        <xsl:text disable-output-escaping="yes">&lt;td class=&quot;rating</xsl:text><xsl:value-of select="normalize-space(ease_number)"/><xsl:text disable-output-escaping="yes">&quot;&gt;</xsl:text><xsl:value-of select="normalize-space(ease_text)"/><xsl:text disable-output-escaping="yes">&lt;/td&gt;</xsl:text>
                        <xsl:text disable-output-escaping="yes">&lt;td class=&quot;rating</xsl:text><xsl:value-of select="normalize-space(confidence_number)"/><xsl:text disable-output-escaping="yes">&quot;&gt;</xsl:text><xsl:value-of select="normalize-space(confidence_text)"/><xsl:text disable-output-escaping="yes">&lt;/td&gt;</xsl:text>
                        <xsl:text disable-output-escaping="yes">&lt;td&gt;</xsl:text><xsl:text disable-output-escaping="yes">&lt;a href=&quot;#</xsl:text><xsl:value-of select="normalize-space(title)"/><xsl:text disable-output-escaping="yes">&quot;&gt;</xsl:text><xsl:value-of select="normalize-space(title)"/><xsl:text disable-output-escaping="yes">&lt;/a&gt;</xsl:text><xsl:text disable-output-escaping="yes">&lt;/td&gt;</xsl:text>
                    </tr>
            </xsl:for-each>
                </table>
            
            <h2>Information about this Audit</h2>
            <p>This report was generated on <xsl:value-of select="scaninfo/datetime"/> by version <xsl:value-of select="scaninfo/version"/> of <a href="http://pentestmonkey.net/windows-privesc-check">windows-privesc-check</a>.</p>
            <p>The audit was run as the user <xsl:value-of select="scaninfo/user"/>.</p>
            <p>The following table provides information about this audit:</p>
            <table id="auditinfo">
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
                    <td>Is Domain Controller?</td>
                    <td><xsl:value-of select="scaninfo/is_domain_controller"/></td>
                </tr>

                <tr>
                    <td>IP Addresses</td>
                    <td>
                            <xsl:value-of select="scaninfo/ipaddress"/>
                    </td>
                </tr>

                <tr class="alt">
                    <td>Privesc Mode</td>
                    <td>
                            <xsl:value-of select="scaninfo/privesc_mode"/>
                    </td>
                </tr>

                <tr>
                    <td>Principals considered untrusted (for exploitable_by mode)</td>
                    <td>
                            <xsl:value-of select="scaninfo/exploitable_by"/>
                    </td>
                </tr>
                
                <tr class="alt">
                    <td>Principals considered trusted (for report_untrusted mode)</td>
                    <td>
                            <xsl:value-of select="scaninfo/ignored_users"/>
                    </td>
                </tr>
            </table> 
            
            
            <h2>Escalation Vectors</h2>
            <xsl:for-each select="issues/issue">
                <hr/>
                <h3><xsl:text disable-output-escaping="yes">&lt;a name=&quot;</xsl:text><xsl:value-of select="normalize-space(title)"/><xsl:text disable-output-escaping="yes">&quot;&gt;</xsl:text><xsl:value-of select="normalize-space(title)"/><xsl:text disable-output-escaping="yes">&lt;/a&gt;</xsl:text></h3>
                <table id="ratinginfo">
                    <tr>
                        <td style="width:140px">Impact</td>
                        <xsl:text disable-output-escaping="yes">&lt;td style=&quot;width:90px&quot; class=&quot;rating</xsl:text><xsl:value-of select="normalize-space(impact_number)"/><xsl:text disable-output-escaping="yes">&quot;&gt;</xsl:text><xsl:value-of select="normalize-space(impact_text)"/><xsl:text disable-output-escaping="yes">&lt;/td&gt;</xsl:text>
                    </tr>
                    <tr>
                        <td>Ease of exploitation</td>
                        <xsl:text disable-output-escaping="yes">&lt;td class=&quot;rating</xsl:text><xsl:value-of select="normalize-space(ease_number)"/><xsl:text disable-output-escaping="yes">&quot;&gt;</xsl:text><xsl:value-of select="normalize-space(ease_text)"/><xsl:text disable-output-escaping="yes">&lt;/td&gt;</xsl:text>
                    </tr>
                    <tr>
                        <td>Confidence</td>
                        <xsl:text disable-output-escaping="yes">&lt;td class=&quot;rating</xsl:text><xsl:value-of select="normalize-space(confidence_number)"/><xsl:text disable-output-escaping="yes">&quot;&gt;</xsl:text><xsl:value-of select="normalize-space(confidence_text)"/><xsl:text disable-output-escaping="yes">&lt;/td&gt;</xsl:text>
                    </tr>
                </table>
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
            
            <h2>Appendices</h2>
            <xsl:for-each select="appendices/appendix">
                <hr/>
                <h3><xsl:text disable-output-escaping="yes">&lt;a name=&quot;appendix:</xsl:text><xsl:value-of select="@title"/><xsl:text disable-output-escaping="yes">&quot;&gt;</xsl:text><xsl:value-of select="@title"/><xsl:text disable-output-escaping="yes">&lt;/a&gt;</xsl:text></h3>
                    <xsl:for-each select="preamble">
                                <p><xsl:value-of select="."/></p>
                    </xsl:for-each>
                    <xsl:for-each select="table">
                        <table id="ratinginfo">
                        <xsl:for-each select="row">
                            <tr>
                            <xsl:for-each select="cell">
                                <td><xsl:value-of select="."/></td>
                            </xsl:for-each>
                            </tr>
                        </xsl:for-each>
                    </table>
                    </xsl:for-each>
            </xsl:for-each>

            <h2>Rating Definitions</h2>
            <xsl:for-each select="ratings/ratingtype">
                <hr/>
                <h3><xsl:text disable-output-escaping="yes">&lt;a name=&quot;ratingtype</xsl:text><xsl:value-of select="@name"/><xsl:text disable-output-escaping="yes">&quot;&gt;</xsl:text><xsl:value-of select="@name"/><xsl:text disable-output-escaping="yes">&lt;/a&gt;</xsl:text></h3>
                    <table id="ratinginfo">
                        <tr>
                            <td><b>Level</b></td>
                            <td><b>Name</b></td>
                            <td><b>Description</b></td>
                        </tr>
                    <xsl:for-each select="ratinglevel">
                        <tr>
                            <xsl:text disable-output-escaping="yes">&lt;td class=&quot;rating</xsl:text><xsl:value-of select="normalize-space(@level)"/><xsl:text disable-output-escaping="yes">&quot;&gt;</xsl:text><xsl:value-of select="normalize-space(@level)"/><xsl:text disable-output-escaping="yes">&lt;/td&gt;</xsl:text>
                            <xsl:text disable-output-escaping="yes">&lt;td class=&quot;rating</xsl:text><xsl:value-of select="normalize-space(@level)"/><xsl:text disable-output-escaping="yes">&quot;&gt;</xsl:text><xsl:value-of select="normalize-space(@name)"/><xsl:text disable-output-escaping="yes">&lt;/td&gt;</xsl:text>
                            <xsl:text disable-output-escaping="yes">&lt;td class=&quot;rating</xsl:text><xsl:value-of select="normalize-space(@level)"/><xsl:text disable-output-escaping="yes">&quot;&gt;</xsl:text><xsl:value-of select="normalize-space(@description)"/><xsl:text disable-output-escaping="yes">&lt;/td&gt;</xsl:text>
                        </tr>
                    </xsl:for-each>
                    </table>
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

    def get_appendices(self):
        return self.appendices

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
        r = etree.Element('report', xmlschemaversion = "1.3")
        # etree.SubElement(r, 'xmlschemaversion').text = "1.0"
        s = etree.Element('scaninfo')
        for k in self.get_info().keys():
            i = etree.Element(k)
            i.text = self.get_info_item(k)
            s.append(i)
        r.append(s)
        r.append(self.get_issues().as_xml())
        ratings = etree.Element('ratings')
        for section_name in wpc.conf.rating_descriptions.keys():
            ratingtype = etree.Element('ratingtype', name = section_name)
            for k in wpc.conf.rating_descriptions[section_name]:
                #i = etree.Element()
                ratinglevel = etree.Element("ratinglevel", level = str(k), name = wpc.conf.rating_mappings[section_name][k], description = wpc.conf.rating_descriptions[section_name][k])
                ratingtype.append(ratinglevel)
            ratings.append(ratingtype)
        r.append(ratings)
        r.append(self.get_appendices().as_xml())
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
