import socketio
import time
import os

# External
from config import PLUS, WARNING, INFO, LESS, LINE, FORBI, BACK

def validate(input_msg):
    try:
        res = raw_input(input_msg)
    except:
        res = input(input_msg)
    return (res in ["y", "Y"])

class check_socketio:

    sio = socketio.Client()
    dynamic_function_number = 0

    FUNC_TEMPLATE = """def on_message_{0}(msg): print(PLUS + "Websocket event found ! => " + msg)"""
    DECORATOR_TEMPLATE = """on_message_{0} = (self.sio.on('{1}'))(on_message_{0})"""

    socketio_paths = []
    custom_event_names = []

    LISTEN_TO_EVENTS_MSG = """Do you want to listen to potential upcoming msg ? [y/N] """
    LISTEN_TO_EVENTS_TIME = """How much time do you want to listen to events ? [time in seconds] """

    def __init__(self):
        self.socketio_paths = [
            "socket.io", "socketio", "io", "socket"
        ]
        self.custom_event_names = [
            "msg", "message", "chat", "login", "logout", "token", "ticket", "admin", "messages",
            "ticket-reload"
        ]

    def connect(self, url, path):
        try:
            self.sio.connect(url, socketio_path=path)
            return True
        except Exception as e:
            pass
        return False

    def disconnect(self):
        try:
            self.sio.disconnect()
        except:
            pass

    def create_function_msg(self, msg):
        exec(self.FUNC_TEMPLATE.format(self.dynamic_function_number))
        exec(self.DECORATOR_TEMPLATE.format(self.dynamic_function_number, msg))
        self.dynamic_function_number += 1

    def run(self, url, directory=None):
        print(LINE)
        print("{}Check for websockets".format(INFO))
        print(LINE)
        filedesc = None
        if (directory):
            filedesc = open("{}/socketio.txt".format(directory), "a+")
        for path in self.socketio_paths:
            if (self.connect(url, path)):
                print("{} {}{} found !".format(PLUS, url, path))
                if (filedesc):
                    filedesc.write("{}\n".format(path))
                if (not validate(self.LISTEN_TO_EVENTS_MSG)):
                    self.disconnect()
                    continue
                for event in self.custom_event_names:
                    self.create_function_msg(event)
                try:
                    time_to_wait = int(raw_input(self.LISTEN_TO_EVENTS_TIME), 10)
                except:
                    time_to_wait = int(input(self.LISTEN_TO_EVENTS_TIME), 10)
                time.sleep(time_to_wait)
                self.disconnect()
