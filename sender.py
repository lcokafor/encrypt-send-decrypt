"""Asymmetric encryption and sending over network exercise.
A public key is sent from a 'receiver', a message is encrypted using that public
key, then encrypted message is sent to receiver. Receiving and sending is done
using a UDP socket."""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import socket

message = "Hello!"

def encrypt_message(public_key):
    """
    Args:
        public_key: public key from receiver

    Returns:
        encrypted_message: message encrypted using public key from receiver
    """
    print("encrypt_message()")
    encrypted_message = public_key.encrypt(
                                message,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None))

    return encrypted_message

def send_message(sock, encrypted_message):
    """
    Args:
        sock: UDP socket used to send message
        encrypted_message: message encrypted using public key from receiver
    """
    print("send_message()")
    UDP_IP = "127.0.0.1"
    SEND_PORT = 2001
    sock.sendto(encrypted_message, (UDP_IP, SEND_PORT))
    sock.close()

def receive_public_key(sock):
    """
    Receives public key through UDP socket.

    Args:
        sock: receiving socket

    Returns:
        public key: public key
    """
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
    """
    Makes socket and binds it to chosen port. Port address is reusable to make
    repeated uses of program easier. Things can only be sent back and forth
    on same network since IP address is 127.0.0.1.
    """
    print("make_socket()")
    UDP_IP = "127.0.0.1"
    UDP_PORT = 2000

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((UDP_IP, UDP_PORT))

    return sock

def main():
    sock = make_socket()
    public_key = receive_public_key(sock)
    encrypted_message = encrypt_message(public_key)
    send_message(sock, encrypted_message)


if __name__ == '__main__':
    main()
