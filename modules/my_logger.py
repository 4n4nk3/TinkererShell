# Written By Ananke: https://github.com/4n4nk3
import datetime

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
