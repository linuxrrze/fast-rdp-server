#!/bin/sh
# xrdp session start script (sesman.ini: UserWindowManager/DefaultWindowManager).
# The broker writes the chosen X11 desktop to /run/fastrdp/desktop/<user>
# (an xsession name, i.e. /usr/share/xsessions/<name>.desktop).

# shellcheck source=/dev/null
if [ -r /etc/profile ]; then . /etc/profile; fi
# shellcheck source=/dev/null
if [ -r "$HOME/.profile" ]; then . "$HOME/.profile"; fi

choice=""
if [ -r "/run/fastrdp/desktop/$USER" ]; then
    choice=$(head -n1 "/run/fastrdp/desktop/$USER" | tr -cd 'A-Za-z0-9._-')
fi
desktop_file="/usr/share/xsessions/${choice:-xfce}.desktop"
[ -f "$desktop_file" ] || desktop_file="/usr/share/xsessions/xfce.desktop"

exec_line=$(sed -n 's/^Exec=//p' "$desktop_file" | head -n1)
names=$(sed -n 's/^DesktopNames=//p' "$desktop_file" | head -n1 | tr ';' ':')
export XDG_SESSION_TYPE=x11
export XDG_SESSION_DESKTOP="${choice:-xfce}"
export DESKTOP_SESSION="${choice:-xfce}"
[ -n "$names" ] && export XDG_CURRENT_DESKTOP="${names%:}"

# shellcheck disable=SC2086 # Exec= lines are word-split like a desktop launcher would
exec dbus-run-session -- $exec_line
