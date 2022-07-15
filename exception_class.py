from logger_module import *
#!/usr/bin/python3

class CommandRunError(Exception):
    def __init__(self, msg):
        self.msg = msg