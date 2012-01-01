<?xml version="1.0" encoding="ISO-8859-1"?>
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