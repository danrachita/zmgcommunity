
Debian
====================
This directory contains files used to package zmgd/zmg-qt
for Debian-based Linux systems. If you compile zmgd/zmg-qt yourself, there are some useful files here.

## zmg: URI support ##


zmg-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install zmg-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your zmgqt binary to `/usr/bin`
and the `../../share/pixmaps/zmg128.png` to `/usr/share/pixmaps`

zmg-qt.protocol (KDE)

