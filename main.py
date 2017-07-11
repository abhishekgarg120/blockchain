import base64
import json
import os
import socket
import datetime
import threading

from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


class SubscribeThread(threading.Thread):
    def __init__(self, blockchain):
        threading.Thread.__init__(self)

        self.blockchain = blockchain
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind((self.blockchain.udp_ip, self.blockchain.udp_port))

    def run(self):
        while True:
            recv = self.sock.recvfrom(2048)
            transaction = json.loads(recv[0])

            if self.blockchain.verify_signature(transaction) and self.blockchain.verify_transaction(transaction):
                self.blockchain.commit_transaction(transaction)
                print(transaction)
            else:
                print("Invalid Transaction")


class PublishThread(threading.Thread):
    def __init__(self, blockchain):
        threading.Thread.__init__(self)

        self.daemon = True
        self.blockchain = blockchain
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def send(self, transaction):
        self.sock.sendto(json.dumps(transaction), ("<broadcast>", self.blockchain.udp_port))


class Blockchain:
    def __init__(self, username, password):
        # create a new hash for identity
        _hash = SHA256.new()
        _hash.update(username.encode())
        _hash.update(password.encode())

        self.root_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), username)
        self.identity = _hash.hexdigest()
        self.private_key = None
        self.udp_ip = ""
        self.udp_port = 50500
        self.transactions = []
        self.public_keys = {}

        self.get_private_key()
        self.get_transactions()

        self.subscribe_thread = SubscribeThread(self)
        self.publish_thread = PublishThread(self)

        self.subscribe_thread.start()
        self.publish_thread.start()

    def get_private_key(self):
        if not os.path.exists(self.root_dir):
            os.makedirs(self.root_dir)

        file_path = os.path.join(self.root_dir, "private_key.pem")

        if os.path.exists(file_path):
            self.private_key = RSA.importKey(open(file_path, "r").read())
        else:
            random = Random.new().read
            self.private_key = RSA.generate(2048, random)

            with open(file_path, "w") as _f:
                _f.write(self.private_key.exportKey())
                _f.close()

        return True

    def get_transactions(self):
        file_path = os.path.join(self.root_dir, "transactions.json")

        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                self.transactions = json.loads(f.read())
                f.close()
        else:
            self.transactions = [{"id": "0".zfill(64)}]

        return True

    def get_public_keys(self):
        file_path = os.path.join(os.path.dirname(self.root_dir), "public_keys.json")

        with open(file_path, 'rw') as f:
            self.public_keys = json.loads(f.read())
            if self.identity not in self.public_keys:
                self.public_keys[self.identity] = self.private_key.publickey().exportKey()
                f.write(json.dumps(self.public_keys))

            f.close()

        return True

    def create_signature(self, data):
        digest = SHA256.new(json.dumps(data))
        signer = PKCS1_v1_5.new(self.private_key)

        return signer.sign(digest)

    def verify_signature(self, data):
        identity = data["data"]["from"]
        signature = data["signature"]

        if identity in self.public_keys:
            public_key = self.public_keys[identity]

            digest = SHA256.new(json.dumps(data))
            public_key = RSA.importKey(public_key)

            verifier = PKCS1_v1_5.new(public_key)
            signature = base64.b64decode(signature)

            return verifier.verify(digest, signature)

        else:
            print("Missing Public Key")
            return False

    def init_transaction(self, to, amount):
        prev_transaction = self.transactions[-1]

        transaction = {
            "data": {
                "from": self.identity,
                "to": to,
                "amount": amount,
                "prev_id": prev_transaction["id"],
                "datetime": datetime.datetime.utcnow().isoformat()
            }
        }

        signature = str(base64.b64encode(self.create_signature(transaction["data"])))

        transaction.update({
            "id": SHA256.new(json.dumps(transaction["data"])).hexdigest(),
            "identity": self.identity,
            "signature": signature,
        })

        self.publish_thread.send(transaction)

    def verify_transaction(self, transaction):
        prev_transaction = self.transactions[-1]
        transaction_id = SHA256.new(json.dumps(transaction["data"])).hexdigest()

        assert transaction_id == transaction["id"], "Invalid Entry"
        assert prev_transaction["id"] == transaction["data"]["prev_id"], "Invalid Previous Entry"

        self.commit_transaction(transaction)

        return True

    def commit_transaction(self, transaction):
        self.transactions.append(transaction)

        with open(os.path.join(self.root_dir, "transactions.json"), "w") as f:
            f.write(json.dumps(self.transactions, indent=2))
            f.close()

        return True
