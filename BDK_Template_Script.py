#!/usr/bin/python3 

import socket 
import binascii 
import string 
from struct import pack 

TCP_IP = "[HSM IP Input]" 
TCP_PORT = 1500  

COMMAND = 'HSM-A01FFFS[Thales Key Input]R%00#B0T2X00N00&N!B'  

#COMMAND = '0000M20011FFFS1009652TN00E0000780B5A0EF222776426FC12A04668BDD59E83C1A268923FC93D4AB75067BB92940668AA40DEE2ECA590610033A95C44D8760000601007C8725A97F8A69372E89D62374001831D88773711A2E129FBB62 736D858D62D01D0CB5EDF1E7710B68FC6CA1C4AE65136C5EFB3F8FA4161301A5156D0253A9536193612574BF021AD948B2A73D26FAC5785094C6945405F5503DB72EB3458DE5BDCAF77E65B2EA1F3556909ACF1C8E6D0636C127956B3CD8D68BDA6B6961E E1D' 

def c_Printable(s): 
    return all(c in string.printable for c in s.decode('ascii', errors='ignore')) 

def buildCommand(command): 
    hCommand = b'' 
    i = 0 
    while i < len(command): 
        if command[i] == '<': 
            i += 1 
            while command[i] != '>': 
                hCommand += binascii.unhexlify(command[i:i+2]) 
                i += 2 
            i += 1 
        else: 
            hCommand += command[i].encode() 
            i += 1 
    return hCommand 

def main(): 
    global TCP_IP 
    global TCP_PORT 
    global COMMAND 

    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    connection.connect((TCP_IP, TCP_PORT)) 

    BUFFER_SIZE = 1024 
    COMMAND = buildCommand(COMMAND) 
    SIZE = pack('>h', len(COMMAND)) 
    MESSAGE = SIZE + COMMAND 
    connection.send(MESSAGE)
