# -*- mode: python -*-
def Datafiles(*filenames, **kw):
    import os
    
    def datafile(path, strip_path=True):
        parts = path.split('/')
        path = name = os.path.join(*parts)
        if strip_path:
            name = os.path.basename(path)
        return name, path, 'DATA'

    strip_path = kw.get('strip_path', True)
    return TOC(
        datafile(filename, strip_path=strip_path)
        for filename in filenames
        if os.path.isfile(filename))

a = Analysis([os.path.join(HOMEPATH,'support\\_mountzlib.py'), os.path.join(HOMEPATH,'support\\useUnicode.py'), 'C:\\wpc2\\windows-privesc-check\\windows_privesc_check.py'],
             pathex=['C:\\pyinstaller-1.5-rc2'])
a.datas = Tree('c:\\wpc2\\windows-privesc-check\\xsl')
pyz = PYZ(a.pure)
exe = EXE( pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
		  Datafiles('/wpc2/windows-privesc-check/xsl/html.xsl', '/wpc2/windows-privesc-check/xsl/text.xsl'),
          name=os.path.join('dist', 'windows_privesc_check.exe'),
          debug=False,
          strip=False,
          upx=True,
          console=True , resources=[],
		  )
		  
		
