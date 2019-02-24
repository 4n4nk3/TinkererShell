#!/usr/bin/env python
"""A simple crossplatform autostart helper"""

# Module for autostart written by Jonas Wagner
# http://29a.ch/2009/3/17/autostart-autorun-with-python

# Example:
# import os
# import autorun
# autorun.add("myapp", os.path.abspath(__file__))

from __future__ import with_statement

import os
import sys

if sys.platform == 'win32':
    import _winreg
    _registry = _winreg.ConnectRegistry(None, _winreg.HKEY_CURRENT_USER)
    def get_runonce():
        return _winreg.OpenKey(_registry,
                r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
        _winreg.KEY_ALL_ACCESS)

    def add(name, application):
        """add a new autostart entry"""
        key = get_runonce()
        _winreg.SetValueEx(key, name, 0, _winreg.REG_SZ, application)
        _winreg.CloseKey(key)

    def exists(name):
        """check if an autostart entry exists"""
        key = get_runonce()
        exists = True
        try:
            _winreg.QueryValueEx(key, name)
        except WindowsError:
            exists = False
        _winreg.CloseKey(key)
        return exists

    def remove(name):
        """delete an autostart entry"""
        key = get_runonce()
        _winreg.DeleteValue(key, name)
        _winreg.CloseKey(key)
else:
    _xdg_config_home = os.environ.get("XDG_CONFIG_HOME", "~/.config")
    _xdg_user_autostart = os.path.join(os.path.expanduser(_xdg_config_home),
            "autostart")

    def getfilename(name):
        """get the filename of an autostart (.desktop) file"""
        return os.path.join(_xdg_user_autostart, name + ".desktop")

    def add(name, application):
        """add a new autostart entry"""
        desktop_entry = "[Desktop Entry]\n"\
            "Name=%s\n"\
            "Exec=%s\n"\
            "Type=Application\n"\
            "Terminal=false\n" % (name, application)
        with open(getfilename(name), "w") as f:
            f.write(desktop_entry)

    def exists(name):
        """check if an autostart entry exists"""
        return os.path.exists(getfilename(name))

    def remove(name):
        """delete an autostart entry"""
        os.unlink(getfilename(name))

def test():
    assert not exists("test_xxx")
    try:
        add("test_xxx", "test")
        assert exists("test_xxx")
    finally:
        remove("test_xxx")
    assert not exists("test_xxx")

if __name__ == "__main__":
    test()
