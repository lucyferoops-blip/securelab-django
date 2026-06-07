#!/usr/bin/env python3
"""
ShadowSocks Server Implementation
A simple SOCKS5 server with encryption for Termux
"""

import socket
import struct
import hashlib
from Crypto.Cipher import AES
import threading
import sys
import argparse
from datetime import datetime

class ShadowSocksServer:
    def __init__(self, host='0.0.0.0', port=8888, password='sarsam123', method='aes-256-cbc'):
        self.host = host
        self.port = port
        self.password = password
        self.method = method
        self.clients = []
        self.lock = threading.Lock()
        
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
    
    def handle_client(self, client_socket, addr):
        """Handle individual client connection"""
        try:
            print(f"[{datetime.now()}] Client connected: {addr}")
            
            salt = client_socket.recv(16)
            if not salt:
                return
            
            key, iv = self.derive_key(self.password, salt)
            
            encrypted_request = client_socket.recv(1024)
            if not encrypted_request:
                return
            
            request = self.decrypt(encrypted_request, key, iv)
            
            if len(request) < 4:
                return
            
            atyp = request[3]
            
            if atyp == 1:
                if len(request) < 10:
                    return
                addr_data = request[4:8]
                port_data = request[8:10]
                host = '.'.join(map(str, addr_data))
                port = struct.unpack('>H', port_data)[0]
            elif atyp == 3:
                domain_len = request[4]
                domain = request[5:5+domain_len].decode()
                port = struct.unpack('>H', request[5+domain_len:7+domain_len])[0]
                host = domain
            elif atyp == 4:
                if len(request) < 22:
                    return
                addr_data = request[4:20]
                port_data = request[20:22]
                host = ':'.join(hex(struct.unpack('>H', addr_data[i:i+2])[0]) for i in range(0, 16, 2))
                port = struct.unpack('>H', port_data)[0]
            else:
                return
            
            print(f"[{datetime.now()}] Forwarding to {host}:{port}")
            
            try:
                remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_socket.settimeout(5)
                remote_socket.connect((host, port))
                
                response = struct.pack('!BBB', 5, 0, 0)
                encrypted_response = self.encrypt(response, key, iv)
                client_socket.send(encrypted_response)
                
                self.relay_data(client_socket, remote_socket, key, iv)
                
            except Exception as e:
                print(f"[{datetime.now()}] Error connecting to {host}:{port}: {e}")
            finally:
                if 'remote_socket' in locals():
                    remote_socket.close()
                    
        except Exception as e:
            print(f"[{datetime.now()}] Error handling client: {e}")
        finally:
            client_socket.close()
            print(f"[{datetime.now()}] Client disconnected: {addr}")
    
    def relay_data(self, client_socket, remote_socket, key, iv):
        """Relay data between client and remote server"""
        def forward(src, dst, is_client=True):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    
                    if is_client:
                        decrypted = self.decrypt(data, key, iv)
                        dst.sendall(decrypted)
                    else:
                        encrypted = self.encrypt(data, key, iv)
                        dst.sendall(encrypted)
            except:
                pass
            finally:
                try:
                    src.close()
                    dst.close()
                except:
                    pass
        
        t1 = threading.Thread(target=forward, args=(client_socket, remote_socket, True))
        t2 = threading.Thread(target=forward, args=(remote_socket, client_socket, False))
        
        t1.daemon = True
        t2.daemon = True
        
        t1.start()
        t2.start()
        
        t1.join()
        t2.join()
    
    def start(self):
        """Start the server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            print(f"[{datetime.now()}] ShadowSocks Server started on {self.host}:{self.port}")
            print(f"[{datetime.now()}] Password: {self.password}")
            print(f"[{datetime.now()}] Method: {self.method}")
            print(f"[{datetime.now()}] Waiting for connections...")
            
            while True:
                try:
                    client_socket, addr = server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"[{datetime.now()}] Error accepting connection: {e}")
                    
        except Exception as e:
            print(f"[{datetime.now()}] Server error: {e}")
        finally:
            server_socket.close()
            print(f"[{datetime.now()}] Server stopped")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='ShadowSocks Server')
    parser.add_argument('-H', '--host', default='0.0.0.0', help='Server host')
    parser.add_argument('-P', '--port', type=int, default=8888, help='Server port')
    parser.add_argument('-p', '--password', default='sarsam123', help='Connection password')
    parser.add_argument('-m', '--method', default='aes-256-cbc', help='Encryption method')
    
    args = parser.parse_args()
    
    server = ShadowSocksServer(
        host=args.host,
        port=args.port,
        password=args.password,
        method=args.method
    )
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[Server stopped by user]")
        sys.exit(0)
