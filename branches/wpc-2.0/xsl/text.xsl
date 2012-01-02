<?xml version="1.0" encoding="ISO-8859-1"?>
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