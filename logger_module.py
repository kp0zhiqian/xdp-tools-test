import logging
import time
import datetime
# subclass of logging.Formatter
# https://stackoverflow.com/questions/25194864/python-logging-time-since-start-of-program
class RuntimeFormatter(logging.Formatter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.start_time = time.time()
    def formatTime(self, record, datefmt=None):
        duration = datetime.datetime.utcfromtimestamp(record.created - self.start_time)
        elapsed = duration.strftime('%H:%M:%S.%f')[:-3]
        return "{}".format(elapsed)

def fmt_filter(record):
    record.lineno = f'{record.lineno})'
    record.filename = f'({record.filename}:'
    return True

def set_logging():
    logger = logging.getLogger()
    logger.handlers = []
    logger.setLevel(level=logging.DEBUG)
    
    handler = logging.FileHandler("output.log", mode='w')
    handler.setLevel(level=logging.DEBUG)
    formatter = RuntimeFormatter('[%(asctime)s]%(filename)15s%(lineno)-4s -  %(message)s')
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    logger.addFilter(fmt_filter)
    
    return logger
# start logger from here to prevent create a logger instance for every test file
logger = set_logging()