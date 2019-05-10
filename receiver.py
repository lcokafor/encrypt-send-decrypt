from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import socket

def create_keys(prvkf_n, pubkf_n):
    print("create_keys()")
    private_key = rsa.generate_private_key(public_exponent=65537,
                                            key_size=2048,
                                            backend=default_backend())
    public_key = private_key.public_key()

    prvk = private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption())

    private_key_file = open(prvkf_n, 'wb')
    private_key_file.write(prvk)
    private_key_file.close()

    pubk = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    public_key_file = open(pubkf_n, 'wb')
    public_key_file.write(pubk)
    public_key_file.close()

    return private_key_file, public_key_file

def deserialize_pk(pubkf_n):
    print("deserialize_pk()")
    with open(pubkf_n, 'rb') as public_key_file:
        public_key = serialization.load_pem_public_key(
                public_key_file.read(),
                backend=default_backend()
        )


def send_public_key(sock, pubkf_n):
    print("send_public_key()")
    UDP_IP = "127.0.0.1"
    SEND_PORT = 2000

    with open(pubkf_n, 'rb') as public_key_file:
        datagram = public_key_file.read(1024)
        while(datagram):
            sock.sendto(datagram, (UDP_IP, SEND_PORT))
            datagram = public_key_file.read(1024)

def receive_message(sock):
    print("receive_message()")
    encrypted_message, address = sock.recvfrom(1024)
    return encrypted_message

def decrypt_message(encrypted_message, prvkf_n):
    print("decrypt_message()")
    with open(prvkf_n, 'rb') as private_key_file:
        private_key = serialization.load_pem_private_key(
                                                        private_key_file.read(),
                                                        password=None,
                                                        backend=default_backend())

        message = private_key.decrypt(
                                    encrypted_message,
                                    padding.OAEP(
                                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None))

        return message

def make_socket():
    print("make_socket()")
    UDP_IP = "127.0.0.1"
    UDP_PORT = 2001

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((UDP_IP, UDP_PORT))

    return sock

def main():
    prvk_name = 'private_key.pem'
    pubk_name = 'public_key.pem'
    private_key_file, public_key_file = create_keys(prvk_name, pubk_name)
    deserialize_pk(pubk_name)
    sock = make_socket()
    send_public_key(sock, pubk_name)
    encrypted_message = receive_message(sock)
    message = decrypt_message(encrypted_message, prvk_name)
    print(message)



if __name__ == '__main__':
    main()
