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

def parse_bdk_response(response_ascii):
    """Parse the HSM response to extract BDK components from ASCII"""
    try:
        print(f"\n=== Full ASCII Response ===")
        print(f"{response_ascii}")
        
        # Extract BDK components based on the specified format
        
        # a. The last 6 characters are the BDK KCV
        bdk_kcv = response_ascii[-6:]
        print(f"\n=== Extracted BDK Components ===")
        print(f"a. BDK KCV (last 6 characters): {bdk_kcv}")
        
        # b. The 97 characters after "HSM-A100" are the BDK Thales Keyblock
        hsm_a100_index = response_ascii.find("HSM-A100")
        if hsm_a100_index != -1:
            start_index = hsm_a100_index + len("HSM-A100")
            bdk_thales_keyblock = response_ascii[start_index:start_index + 97]
            print(f"b. BDK Thales Keyblock (97 chars after HSM-A100): {bdk_thales_keyblock}")
        else:
            print(f"b. BDK Thales Keyblock: NOT FOUND (HSM-A100 not found)")
            bdk_thales_keyblock = "NOT_FOUND"
        
        # c. The 79 characters after the end of item b, skipping one character, starting with "B0"
        if bdk_thales_keyblock != "NOT_FOUND":
            after_thales_start = start_index + 97 + 1  # +1 to skip one character
            remaining_response = response_ascii[after_thales_start:]
            b0_index = remaining_response.find("B0")
            if b0_index != -1:
                bdk_tr31_start = after_thales_start + b0_index
                bdk_tr31_keyblock = response_ascii[bdk_tr31_start:bdk_tr31_start + 79]
                print(f"c. BDK TR-31 Keyblock (79 chars starting with B0): {bdk_tr31_keyblock}")
            else:
                print(f"c. BDK TR-31 Keyblock: NOT FOUND (B0 not found after Thales keyblock)")
                bdk_tr31_keyblock = "NOT_FOUND"
        else:
            print(f"c. BDK TR-31 Keyblock: NOT FOUND (Thales keyblock not found)")
            bdk_tr31_keyblock = "NOT_FOUND"
        
        return {
            'bdk_kcv': bdk_kcv,
            'bdk_thales_keyblock': bdk_thales_keyblock,
            'bdk_tr31_keyblock': bdk_tr31_keyblock
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
            response_ascii = response.decode('ascii', errors='ignore')
            response_hex = response.hex().upper()
            print(f"Received Data (ASCII): {response_ascii}")
            print(f"Received Data (HEX): {response_hex}")
            
            # Parse the response to extract BDK components from ASCII
            bdk_components = parse_bdk_response(response_ascii)
            
            if bdk_components:
                print(f"\n=== BDK Components Summary ===")
                print(f"BDK KCV: {bdk_components['bdk_kcv']}")
                print(f"BDK Thales Keyblock: {bdk_components['bdk_thales_keyblock']}")
                print(f"BDK TR-31 Keyblock: {bdk_components['bdk_tr31_keyblock']}")
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
