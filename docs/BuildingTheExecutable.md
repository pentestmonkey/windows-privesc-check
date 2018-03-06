The source code for windows-privesc-check is Python.  This page describes how to create a Windows executable (.exe file) using pyinstaller.

# Build in Wine - Kali Linux #
Based on https://medium.com/@jam3s/converting-python-into-exe-files-on-kali-1b1f30ba931f + ntlm fix

# install python for windows
$ wget https://www.python.org/ftp/python/2.7.8/python-2.7.8.msi
$ wine msiexec /i python-2.7.8.msi
$ rm python-2.7.8.msi

# install pywin32
$ wget http://downloads.sourceforge.net/project/pywin32/pywin32/Build%20220/pywin32-220.win32-py2.7.exe
$ wine pywin32-220.win32-py2.7.exe
$ rm pywin32-220.win32-py2.7.exe

# install pyinstaller
$ wget https://github.com/pyinstaller/pyinstaller/releases/download/v2.1/PyInstaller-2.1.zip
$ unzip PyInstaller-2.1.zip -d /opt
$ rm PyInstaller-2.1.zip

$ apt-get install winbind

# convert python to exe
$ cd <windows_privesc_check.py location>
$ wine c:/Python27/python.exe /opt/PyInstaller-2.1/pyinstaller.py --onefile windows_privesc_check.py

Invalid argument Error 22?
Reinstall pywin!

# Install Dependencies #

In order to run windows-privesc-check.exe, you don't need any dependencies installed.  However, to build the .exe yourself, you'll need to following:
  * python: http://www.python.org/download/releases/2.7.1/
  * pyinstaller: http://www.pyinstaller.org/changeset/1352/tags/1.5-rc2?old_path=%2F&format=zip
  * pywin32: http://sourceforge.net/projects/pywin32/files/pywin32/Build%20214/
  * lxml: http://lxml.de/index.html

Other versions will work too - these are just an example of known working versions.

# Build Executable #

  * Unzip pyinstaller to c:\pyinstaller
  * cd c:\pyinstaller
  * python Configure.py
  * python Makespec.py --onefile c:\somepath\windows-privesc-check.py
  * python Build.py windows-privesc-check\windows-privesc-check.spec

This should create the following .exe for you:
windows-privesc-check\dist\window-privesc-check.exe

# Useful Links #

These resources are incredibly useful:
  * pywin32 online docs: http://timgolden.me.uk/pywin32-docs/contents.html
  * pyinstaller docs: http://www.pyinstaller.org/export/latest/tags/1.4/doc/Manual.html?format=raw

The process below was tested on Windows XP.