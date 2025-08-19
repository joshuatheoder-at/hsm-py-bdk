#!/usr/bin/python3 

import socket 
import binascii 
import string 
from struct import pack 
import re

def get_user_inputs():
    """Get HSM IP and Thales Encrypted Key from user"""
    print("=== BDK Generation Script ===\n")
    
    # Get HSM IP
    while True:
        hsm_ip = input("Enter HSM IP Address: ").strip()
        if hsm_ip:
            break
        print("HSM IP cannot be empty. Please try again.")
    
    # Get Thales Encrypted Key
    print("\nHint: The Thales Encrypted Key should be 97 characters long")
    print("Sample: S1009652TN00E0000559CA4D074FB5C95DE59E680C5A0F33E96FCDADB9EBED11DFF5BFA5A24A60923CBD0A3EB992028CC")
    
    while True:
        thales_key = input("\nEnter Thales Encrypted Key: ").strip()
        if len(thales_key) == 97:
            break
        print(f"Invalid length: {len(thales_key)} characters. Expected 97 characters. Please try again.")
    
    return hsm_ip, thales_key

def buildCommand(command):
    """Convert command string with hex values to binary"""
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

def parse_bdk_response(response_hex):
    """Parse the HSM response to extract BDK components"""
    try:
        # Convert hex to ASCII for easier parsing
        response_ascii = binascii.unhexlify(response_hex).decode('ascii', errors='ignore')
        
        print(f"\n=== Parsed Response ===")
        print(f"Full ASCII Response: {response_ascii}")
        print(f"Full HEX Response: {response_hex}")
        
        # Parse BDK Thales Key Block (128 hex chars after HSM-A100S10096B0TX00N0000)
        thales_prefix = "48534d2d413130305331303039364230545830304e30303030"  # HSM-A100S10096B0TX00N0000
        thales_start = response_hex.find(thales_prefix)
        
        if thales_start != -1:
            thales_start += len(thales_prefix)
            bdk_thales = response_hex[thales_start:thales_start + 128]
            print(f"\n1. BDK Thales Key Block: {bdk_thales}")
        else:
            print("\n1. BDK Thales Key Block: NOT FOUND")
            bdk_thales = "NOT_FOUND"
        
        # Parse BDK TR31 Key Block (80 hex chars after RB0080B0TX00N0000)
        tr31_separator = "5242303038304230545830304e30303030"  # RB0080B0TX00N0000
        tr31_start = response_hex.find(tr31_separator)
        
        if tr31_start != -1:
            tr31_start += len(tr31_separator)
            bdk_tr31 = response_hex[tr31_start:tr31_start + 80]
            print(f"2. BDK TR31 Key Block: {bdk_tr31}")
        else:
            print("2. BDK TR31 Key Block: NOT FOUND")
            bdk_tr31 = "NOT_FOUND"
        
        # Parse KCV (last 14 hex chars)
        kcv = response_hex[-14:]
        print(f"3. KCV (Key Check Value): {kcv}")
        
        return {
            'bdk_thales': bdk_thales,
            'bdk_tr31': bdk_tr31,
            'kcv': kcv
        }
        
    except Exception as e:
        print(f"Error parsing response: {e}")
        return None

def main():
    """Main function to execute BDK generation"""
    try:
        # Get user inputs
        hsm_ip, thales_key = get_user_inputs()
        
        # Build the command
        command = f'HSM-A01FFFS{thales_key}R%00#B0T2X00N00&N!B'
        print(f"\n=== Generated Command ===")
        print(f"Command: {command}")
        
        # Convert command to binary
        binary_command = buildCommand(command)
        
        # Connect to HSM
        print(f"\n=== Connecting to HSM ===")
        print(f"Connecting to {hsm_ip}:1500...")
        
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(30)  # 30 second timeout
        connection.connect((hsm_ip, 1500))
        print("Connected successfully!")
        
        # Send command
        print(f"\n=== Sending Command ===")
        size = pack('>h', len(binary_command))
        message = size + binary_command
        
        print(f"Sent Data (ASCII): {binary_command.decode('ascii', errors='ignore')}")
        print(f"Sent Data (HEX): {binary_command.hex().upper()}")
        
        connection.send(message)
        print("Command sent successfully!")
        
        # Receive response
        print(f"\n=== Receiving Response ===")
        response = connection.recv(1024)
        
        if response:
            response_hex = response.hex().upper()
            print(f"Received Data (ASCII): {response.decode('ascii', errors='ignore')}")
            print(f"Received Data (HEX): {response_hex}")
            
            # Parse the response to extract BDK components
            bdk_components = parse_bdk_response(response_hex)
            
            if bdk_components:
                print(f"\n=== BDK Components Summary ===")
                print(f"BDK Thales Key Block: {bdk_components['bdk_thales']}")
                print(f"BDK TR31 Key Block: {bdk_components['bdk_tr31']}")
                print(f"KCV: {bdk_components['kcv']}")
        else:
            print("No response received from HSM")
        
        # Close connection
        connection.close()
        print(f"\nConnection closed.")
        
    except socket.timeout:
        print("Connection timeout. Please check the HSM IP and try again.")
    except socket.error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
