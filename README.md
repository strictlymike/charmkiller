charmkiller
===========
Application for killing Windows "Immersive Experience" user interface, also
known as the charms bar.

Overview
========
Locates explorer.exe, then the windows.immersiveshell.serviceprovider.dll
library within it, and finally the thread within explorer.exe that appears to
host the relevant library, finally terminating that thread.

Note that compiling this source code and executing the resulting binary
terminates not only the charms bar, but also the Start menu (which can be used
to search for programs that are not known by name), the wireless network
configuration bar, and potentially other controls that are useful within
Windows 8.  Consequently, the author does not personally find it particularly
useful, except as a starting point for any future project that might entail
locating and interacting with threads according to the module whose code they
are executing.

Build and Test
==============
Requires Windows 7.1 Platform SDK or equivalent.

Building
--------

To build, check out files, open a Windows SDK command prompt, and type:

`nmake`

Testing
-------

Usage:

`killcharms.exe`

A Windows script is included to restart the Windows shell in the event that an
error results in undesired operation:

`restart_shell.cmd`

License
=======
Licensed under the [WTF Public License](http://www.wtfpl.net/).
