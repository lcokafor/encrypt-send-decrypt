from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import socket

message = "Hello!"

def encrypt_message(public_key):
    print("encrypt_message()")
    encrypted_message = public_key.encrypt(
                                message,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None))

    return encrypted_message

def send_message(sock, encrypted_message):
    print("send_message()")
    SEND_PORT = 2001
    sock.sendto(encrypted_message, (UDP_IP, SEND_PORT))
    sock.close()

def receive_public_key(sock):
    print("receive_public_key()")
    with open('public_key_received.pem', 'wb+') as public_key_file:
        datagram, address = sock.recvfrom(1024)
        public_key_file.write(datagram)
        #datagram, address = sock.recvfrom(1024)

    with open('public_key_received.pem', 'rb') as public_key_file:
        public_key = serialization.load_pem_public_key(
                public_key_file.read(),
                backend=default_backend()
        )

    return public_key

def make_socket():
    print("make_socket()")
    UDP_IP = "127.0.0.1"
    UDP_PORT = 2000

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    return sock

def main():
    sock = make_socket()
    public_key = receive_public_key(sock)
    encrypted_message = encrypt_message(public_key)
    send_message(sock, encrypted_message)


if __name__ == '__main__':
    main()
