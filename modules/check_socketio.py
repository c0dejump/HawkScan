import socketio
import time
import os, sys
import json

# External
from config import PLUS, WARNING, INFO, LESS, LINE, FORBI, BACK


#Thanks Jamb0n69 !

socketio_paths = [
            "socket.io", "socketio", "io", "socket", "signalr", "xmpp-websocket"
        ]


class check_socketio:

    sio = socketio.Client(reconnection=False)
    dynamic_function_number = 0

    FUNC_TEMPLATE = """def on_message_{0}(msg): print(PLUS + "Websocket event found ! => " + msg)"""
    DECORATOR_TEMPLATE = """on_message_{0} = (self.sio.on('{1}'))(on_message_{0})"""


    def connect(self, url, path):
        try:
            #print(path) #DEBUG
            self.sio.connect(url, socketio_path=path)
            return True
        except Exception as e:
            #print(e) #DEBUG
            return e
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

    def run_socketio(self, url, directory=None, first=True):
        found_socket = False
        if first:
            print(LINE)
            print("{} Check for websockets".format(INFO))
            print(LINE)
        filedesc = None
        if (directory):
            filedesc = open("{}/socketio.txt".format(directory), "a+")
        for path in socketio_paths:
            connect = self.connect(url, path)
            if type(connect) == bool and connect == True:
                print(" {} {}{} found !".format(PLUS, url, path))
                domain = url.split("/")[2] if not "www" in url else ".".join(url.split("/")[2].split(".")[1:])
                print(" {} Try this \"\033[36msudo apt install npm -y && npx wscat -c ws://{}/socket.io/?transport=websocket\033[0m\"".format(INFO, domain))
                if filedesc:
                    filedesc.write("{}\n".format(path))
                self.disconnect()
                found_socket = True
            elif not found_socket:
                print(" {} {}: {}".format(LESS, path, connect))
        if not found_socket:
            print("\n {} Nothing Socketio found".format(LESS))


"""if __name__ == '__main__':
    url = sys.argv[1]
    print(url)
    check_socketio = check_socketio()
    check_socketio.run_socketio(url)"""