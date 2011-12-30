<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output method="xml" indent="yes" 
    doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"
    doctype-public="-//W3C//DTD XHTML 1.0 Transitional//EN" />

<xsl:template match="report">
	<html>
		<head>
			<title>Windows Privilege Escalation Report</title>
		</head>
		<body>
		    <h1>Windows Privilege Escalation Report</h1>
			<xsl:for-each select="issue">
				<hr/>
		    	<h2><xsl:value-of select="normalize-space(title)" /></h2>
				<xsl:for-each select="section">
					<h3><xsl:value-of select="@type" /></h3>
					<p><xsl:value-of select="normalize-space(body)"/></p>
					<xsl:apply-templates select="details"/> 
				</xsl:for-each>
			</xsl:for-each>
		</body>
	</html>
</xsl:template>

<xsl:template match="details">
    <p><xsl:value-of select="preamble"/></p>
    <xsl:if test="supporting_data/*">
        <table border="1" width="80%">
	    <xsl:for-each select="supporting_data/data">
	    	<tr><td><xsl:value-of select="normalize-space(.)"/></td></tr>
	    </xsl:for-each>
	    </table>
    </xsl:if>
</xsl:template>

</xsl:stylesheet>