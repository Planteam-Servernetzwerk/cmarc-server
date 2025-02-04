from flask import Flask, abort, jsonify, redirect, render_template, request, g
from flask_httpauth import HTTPBasicAuth
import psql
import datetime as dt
import typing as t
from hashlib import sha256
from nacl.signing import SigningKey
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
import os


IV = b"\x41" * 16


def login(username: str, password: str, ed25519_sk: t.Optional[SigningKey] = None,
          x25519_sk: t.Optional[x25519.X25519PrivateKey] = None, register: bool = False) -> bool:
    password_hash = sha256(password.encode()).digest()

    user = Entity.fetch(name=username)

    if register and ed25519_sk and x25519_sk:
        if user:
            return False

        ed25519_pk = ed25519_sk.verify_key
        x25519_pk = x25519_sk.public_key()

        aes_key = derive_key(password)

        __x25519_sk = x25519_sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        __x25519_pk = x25519_pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        user = Entity(..., username, password_hash, ..., encrypt_aes(ed25519_sk.encode(), aes_key),
                      ed25519_pk.encode(), encrypt_aes(__x25519_sk, aes_key),
                      __x25519_pk)
        user.commit()

        return True

    if not user:
        return False

    if not user.password == password_hash:
        return False

    return True


def pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


def derive_key(passphrase: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"AES database encryption"
    )
    return hkdf.derive(passphrase.encode())


def encrypt_aes(plain_text: bytes, aes_key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(IV))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(pad(plain_text)) + encryptor.finalize()
    return ciphertext


def decrypt_aes(ciphertext: bytes, aes_key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(IV))
    decryptor = cipher.decryptor()
    return unpad(decryptor.update(ciphertext) + decryptor.finalize())


class Entity(psql.SQLObject):
    SERVER_NAME = "hector"
    SCHEMA_NAME = "cmarc"
    TABLE_NAME = "entities"

    SQL_KEYS = ["id", "name", "password", "registration_time", "ed25519_private", "ed25519_public",
                "x25519_private", "x25519_public"]
    PRIMARY_KEY = SQL_KEYS[0]

    def __init__(self, _id: int, name: str, password: bytes, registration_time: dt.datetime, ed25519_private: bytes,
                 ed25519_public: bytes, x25519_private: bytes, x25519_public: bytes):
        super().__init__()
        self.id = _id
        self.name = name
        self.password = password
        self.registration_time = registration_time
        self.ed25519_private = ed25519_private
        self.ed25519_public = ed25519_public
        self.x25519_private = x25519_private
        self.x25519_public = x25519_public

    @staticmethod
    def construct(response) -> list:
        return [Entity(x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]) for x in response]

    def get_ed25519_sk(self, aes_key: bytes) -> bytes:
        return decrypt_aes(self.ed25519_private, aes_key)

    def get_x25519_sk(self, aes_key: bytes) -> bytes:
        return decrypt_aes(self.x25519_private, aes_key)


app = Flask(__name__)
auth = HTTPBasicAuth()


@auth.verify_password
def verify_password(username, password):
    g.current_password = password
    return username if login(username, password) else None


@app.route("/")
def root():
    return render_template("index.html")


@app.route("/generate", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return abort(400)

        seed = sha256(f"{username}:{password}".encode()).digest()
        plain_ed25519_sk = SigningKey(seed)
        plain_x25519_sk = x25519.X25519PrivateKey.generate()

        success = login(username, password, plain_ed25519_sk, plain_x25519_sk, True)

        if not success:
            abort(400)

        return redirect("/")

    return render_template("generate.html")


@app.route("/self")
@auth.login_required
def keys():
    username = auth.current_user()
    user = Entity.get(name=username)
    aes_key = derive_key(g.get("current_password"))
    g.pop("current_password")
    return render_template("keys.html", user=user, aes_key=aes_key)


@app.route("/api/self")
@auth.login_required
def api_keys():
    username = auth.current_user()
    user = Entity.get(name=username)
    aes_key = derive_key(g.get("current_password"))
    g.pop("current_password")
    return jsonify({
        "name": username,
        "ed25519": {
            "sk": user.get_ed25519_sk(aes_key).hex(),
            "pk": user.ed25519_public.hex()
        },
        "x25519": {
            "sk": user.get_x25519_sk(aes_key).hex(),
            "pk": user.x25519_public.hex()
        }
    })


@app.route("/lookup")
def lookup():
    users = Entity.gets()
    return render_template("lookup.html", users=users)


@app.route("/api/lookup", defaults={"name": None})
@app.route("/api/lookup/<name>")
def api_lookup(name):
    if name:
        obj = Entity.get(name=name)
        return jsonify({
            "name": obj.name,
            "ed25519_pk": obj.ed25519_public.hex(),
            "x25519_pk": obj.x25519_public.hex()
        })

    objs = Entity.gets()
    return jsonify([{
        "name": obj.name,
        "ed25519_pk": obj.ed25519_public.hex(),
        "x25519_pk": obj.x25519_public.hex()
    } for obj in objs])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9980, debug=True)

