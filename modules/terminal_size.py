import fcntl, termios, struct
import sys

def terminal_size():
    #to define size of terminal used
    if sys.stdout.isatty():
        th, tw, hp, wp = struct.unpack('HHHH',
            fcntl.ioctl(0, termios.TIOCGWINSZ,
            struct.pack('HHHH', 0, 0, 0, 0)))
        return tw, th
    else:
        return 0, 0