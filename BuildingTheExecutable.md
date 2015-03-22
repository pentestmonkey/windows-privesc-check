The source code for windows-privesc-check is Python.  This page describes how to create a Windows executable (.exe file) using pyinstaller.

The process below was tested on Windows XP.

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