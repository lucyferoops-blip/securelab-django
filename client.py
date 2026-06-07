#!/usr/bin/env python3
"""
ShadowSocks Client Implementation
"""

import socket
import struct
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys

class ShadowSocksClient:
    def __init__(self, server_host, server_port, password='sarsam123', method='aes-256-cbc'):
        self.server_host = server_host
        self.server_port = server_port
        self.password = password
        self.method = method
    
    def derive_key(self, password, salt):
        """Derive encryption key from password"""
        m = []
        i = 0
        while len(b''.join(m)) < 48:
            md5 = hashlib.md5()
            data = password.encode() if isinstance(password, str) else password
            if i == 0:
                md5.update(data + salt)
            else:
                md5.update(m[i - 1] + data + salt)
            m.append(md5.digest())
            i += 1
        ms = b''.join(m)
        return ms[:32], ms[32:48]
    
    def encrypt(self, data, key, iv):
        """Encrypt data using AES"""
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pad_len = 16 - (len(data) % 16)
        padded_data = data + bytes([pad_len] * pad_len)
        return cipher.encrypt(padded_data)
    
    def decrypt(self, data, key, iv):
        """Decrypt data using AES"""
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(data)
        pad_len = decrypted[-1]
        return decrypted[:-pad_len]
    
    def connect_to_host(self, host, port):
        """Connect to a remote host through the VPN"""
        try:
            # Connect to VPN server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.server_host, self.server_port))
            
            # Generate salt and derive key
            salt = get_random_bytes(16)
            key, iv = self.derive_key(self.password, salt)
            
            # Send salt
            sock.send(salt)
            
            # Create SOCKS5 request
            # Format: [VER=1][CMD=1][RSV=1][ATYP=1][DST.ADDR][DST.PORT]
            request = bytes([5, 1, 0, 1])
            request += socket.inet_aton(host)
            request += struct.pack('>H', port)
            
            # Encrypt and send request
            encrypted_request = self.encrypt(request, key, iv)
            sock.send(encrypted_request)
            
            # Receive response
            encrypted_response = sock.recv(1024)
            response = self.decrypt(encrypted_response, key, iv)
            
            if response[1] == 0:
                print(f"✅ Connected to {host}:{port} through VPN")
                return sock, key, iv
            else:
                print(f"❌ Connection failed")
                return None, None, None
                
        except Exception as e:
            print(f"❌ Error: {e}")
            return None, None, None
    
    def send_request(self, sock, data, key, iv):
        """Send encrypted request"""
        encrypted = self.encrypt(data, key, iv)
        sock.send(encrypted)
    
    def receive_response(self, sock, key, iv):
        """Receive encrypted response"""
        encrypted = sock.recv(4096)
        if encrypted:
            return self.decrypt(encrypted, key, iv)
        return None

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python3 client.py <host> <port>")
        print("Example: python3 client.py google.com 80")
        sys.exit(1)
    
    target_host = sys.argv[1]
    target_port = int(sys.argv[2])
    
    # VPN server info
    vpn_server = '127.0.0.1'
    vpn_port = 8888
    vpn_password = 'sarsam123'
    
    client = ShadowSocksClient(vpn_server, vpn_port, vpn_password)
    sock, key, iv = client.connect_to_host(target_host, target_port)
    
    if sock:
        print(f"Connected! Now you can send data...")
        sock.close()
    else:
        print("Failed to connect")
