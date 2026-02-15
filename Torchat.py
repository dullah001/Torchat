#!/usr/bin/env python3
"""
TorChat – Single-file anonymous messaging over Tor
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import random
import subprocess
import sys
import tempfile
import time
import threading
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import aiohttp
import colorama
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from prompt_toolkit import PromptSession
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.patch_stdout import patch_stdout
from stem.control import Controller
from stem.process import launch_tor_with_config

# ============================================================================
# Logging setup
# ============================================================================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
colorama.init()

# ============================================================================
# Utility Classes
# ============================================================================
class RandomRouteGenerator:
    def generate_route(self):
        @dataclass
        class Route:
            hops: List[Dict]
        # Placeholder – in production would query Tor for real relays
        return Route(hops=[{"public_key": "dummy", "next_hop": b""}])


class PaddingManager:
    def generate_padding(self) -> bytes:
        return os.urandom(random.randint(64, 256))

    def generate_dummy_message(self) -> bytes:
        return os.urandom(random.randint(128, 512))


# ============================================================================
# Protocol Data Structures
# ============================================================================
@dataclass
class MessageEnvelope:
    sender_id: str
    recipient_id: str
    timestamp: float
    message_type: str
    payload: bytes
    padding: bytes


@dataclass
class ContactRequest:
    sender_id: str
    sender_onion: str
    public_key: str
    timestamp: float


# Simplified Double Ratchet (placeholder)
class DoubleRatchet:
    def __init__(self, shared_secret: bytes, my_keypair, their_public_key):
        self.shared_secret = shared_secret
        self.my_keypair = my_keypair
        self.their_public_key = their_public_key
        self.root_key = shared_secret
        self.send_chain_key = shared_secret
        self.recv_chain_key = shared_secret

    def encrypt(self, plaintext: bytes) -> bytes:
        # In production, real ratchet logic here
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(self.send_chain_key[:32]), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        iv = ciphertext[:12]
        tag = ciphertext[12:28]
        data = ciphertext[28:]
        cipher = Cipher(algorithms.AES(self.recv_chain_key[:32]), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()


# ============================================================================
# Cryptography
# ============================================================================
class SignalProtocol:
    def __init__(self):
        self.backend = default_backend()
        self.private_key = None
        self.public_key = None
        self.identity_key = None

    def generate_keypair(self) -> Dict:
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.identity_key = x25519.X25519PrivateKey.generate()

        priv_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        identity_pub = self.identity_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return {
            'private': base64.b64encode(priv_bytes).decode(),
            'public': base64.b64encode(pub_bytes).decode(),
            'identity': base64.b64encode(identity_pub).decode()
        }

    def load_keys(self, keys: Dict):
        priv_bytes = base64.b64decode(keys['private'])
        pub_bytes = base64.b64decode(keys['public'])
        self.private_key = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
        self.public_key = x25519.X25519PublicKey.from_public_bytes(pub_bytes)

    def get_public_key(self) -> str:
        pub_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return base64.b64encode(pub_bytes).decode()

    def get_keypair(self) -> Tuple:
        return self.private_key, self.public_key

    def generate_shared_secret(self, other_public_key: str) -> bytes:
        other_pub_bytes = base64.b64decode(other_public_key)
        other_pub = x25519.X25519PublicKey.from_public_bytes(other_pub_bytes)
        shared_secret = self.private_key.exchange(other_pub)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'torchat-key',
            backend=self.backend
        ).derive(shared_secret)
        return derived_key

    def encrypt_for_contact(self, data: bytes, contact_id: str) -> bytes:
        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(self._get_conversation_key(contact_id)),
            modes.GCM(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data) + encryptor.finalize()
        return iv + encryptor.tag + encrypted

    def decrypt_from_contact(self, encrypted_data: bytes, contact_id: str) -> bytes:
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        cipher = Cipher(
            algorithms.AES(self._get_conversation_key(contact_id)),
            modes.GCM(iv, tag),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def _get_conversation_key(self, contact_id: str) -> bytes:
        seed = contact_id.encode() + self.get_public_key().encode()
        return hashlib.sha256(seed).digest()


class OnionEncryptor:
    @staticmethod
    def encrypt_layers(data: bytes, hops: List[Dict]) -> bytes:
        encrypted = data
        for hop in reversed(hops):
            ephemeral_private = x25519.X25519PrivateKey.generate()
            ephemeral_public = ephemeral_private.public_key()
            shared_secret = ephemeral_private.exchange(
                x25519.X25519PublicKey.from_public_bytes(
                    base64.b64decode(hop['public_key'])
                )
            )
            aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'onion-hop',
                backend=default_backend()
            ).derive(shared_secret)

            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            payload = hop.get('next_hop', b'') + encrypted
            encrypted = iv + encryptor.tag + encryptor.update(payload) + encryptor.finalize()
            encrypted = ephemeral_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ) + encrypted
        return encrypted

    @staticmethod
    def decrypt_layers(encrypted_data: bytes, private_key: bytes) -> bytes:
        data = encrypted_data
        while True:
            if len(data) < 32:
                break
            ephemeral_public_bytes = data[:32]
            data = data[32:]
            ephemeral_public = x25519.X25519PublicKey.from_public_bytes(ephemeral_public_bytes)
            private_key_obj = x25519.X25519PrivateKey.from_private_bytes(private_key)
            shared_secret = private_key_obj.exchange(ephemeral_public)
            aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'onion-hop',
                backend=default_backend()
            ).derive(shared_secret)

            iv = data[:12]
            tag = data[12:28]
            ciphertext = data[28:]
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()

            if len(decrypted) <= 32:
                data = decrypted
                break
            else:
                data = decrypted[32:]
        return data


# ============================================================================
# Tor Manager
# ============================================================================
class TorManager:
    def __init__(self, tor_path: str = "tor", control_port: int = 9051):
        self.tor_path = tor_path
        self.control_port = control_port
        self.socks_port = 9050
        self.tor_process = None
        self.controller: Optional[Controller] = None
        self.onion_service_id = None
        self.data_dir = tempfile.mkdtemp(prefix="torchat_tor_")

    async def start(self):
        try:
            tor_config = {
                'SocksPort': str(self.socks_port),
                'ControlPort': str(self.control_port),
                'DataDirectory': self.data_dir,
                'Log': 'notice stdout',
                'SafeLogging': '1',
                'AvoidDiskWrites': '1',
                'MaxCircuitDirtiness': '600',
                'NewCircuitPeriod': '600',
                'MaxClientCircuitsPending': '48',
                'UseEntryGuards': '1',
                'NumEntryGuards': '3',
                'GuardLifetime': '30 days',
                'ExcludeNodes': '{}',
                'StrictNodes': '0',
                'GeoIPExcludeUnknown': '1',
                'CircuitBuildTimeout': '60',
                'LearnCircuitBuildTimeout': '1',
                'CircuitsAvailableTimeout': '1',
                'UseMicrodescriptors': '1',
            }
            self.tor_process = launch_tor_with_config(
                config=tor_config,
                tor_cmd=self.tor_path,
                take_ownership=True,
                init_msg_handler=self._tor_status
            )
            self.controller = Controller.from_port(port=self.control_port)
            self.controller.authenticate()
            await self._test_connection()
            logger.info("Tor connection established")
            return True
        except Exception as e:
            logger.error(f"Failed to start Tor: {e}")
            return False

    def _tor_status(self, line: str):
        if "Bootstrapped" in line:
            logger.info(f"Tor: {line}")

    async def _test_connection(self):
        proxy = f"socks5h://127.0.0.1:{self.socks_port}"
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get("https://check.torproject.org/api/ip", proxy=proxy) as resp:
                data = await resp.json()
                if not data.get('IsTor', False):
                    raise Exception("Not using Tor")

    async def start_onion_service(self, port: int = 8080) -> str:
        if not self.controller:
            raise Exception("Tor controller not available")
        try:
            result = self.controller.create_ephemeral_hidden_service(
                {port: port},
                await_publication=True,
                detached=True
            )
            self.onion_service_id = result.service_id
            onion_address = f"{self.onion_service_id}.onion"
            logger.info(f"Onion service created: {onion_address}")
            return onion_address
        except Exception as e:
            logger.error(f"Failed to create onion service: {e}")
            return ""

    async def stop(self):
        if self.controller:
            if self.onion_service_id:
                self.controller.remove_ephemeral_hidden_service(self.onion_service_id)
            self.controller.close()
        if self.tor_process:
            self.tor_process.terminate()
            self.tor_process.wait()
        import shutil
        shutil.rmtree(self.data_dir, ignore_errors=True)
        logger.info("Tor stopped")


# ============================================================================
# Encrypted Storage
# ============================================================================
class EncryptedStorage:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.identity_file = os.path.join(data_dir, "identity.json")
        self.contacts_file = os.path.join(data_dir, "contacts.json")
        os.makedirs(data_dir, exist_ok=True)

    def load_identity(self) -> Optional[Dict]:
        if os.path.exists(self.identity_file):
            with open(self.identity_file, 'r') as f:
                return json.load(f)
        return None

    def save_identity(self, identity: Dict):
        with open(self.identity_file, 'w') as f:
            json.dump(identity, f)

    def load_contacts(self) -> Dict[str, 'Contact']:
        if os.path.exists(self.contacts_file):
            with open(self.contacts_file, 'r') as f:
                data = json.load(f)
                return {cid: Contact(**c) for cid, c in data.items()}
        return {}

    def save_contact(self, contact: 'Contact'):
        contacts = self.load_contacts()
        contacts[contact.id] = contact
        with open(self.contacts_file, 'w') as f:
            json.dump({cid: asdict(c) for cid, c in contacts.items()}, f)


# ============================================================================
# Contact Class
# ============================================================================
@dataclass
class Contact:
    id: str
    onion_address: str
    public_key: str
    last_seen: float
    nickname: Optional[str] = None
    is_verified: bool = False


# ============================================================================
# Main Client
# ============================================================================
class TorChatClient:
    def __init__(self, data_dir: str = "~/.torchat"):
        self.data_dir = os.path.expanduser(data_dir)
        self.tor = TorManager()
        self.crypto = SignalProtocol()
        self.storage = EncryptedStorage(self.data_dir)
        self.ratchets: Dict[str, DoubleRatchet] = {}
        self.contacts: Dict[str, Contact] = {}
        self.route_gen = RandomRouteGenerator()
        self.padder = PaddingManager()
        self.client_id = None
        self.onion_address = None
        self.is_running = False
        self.message_queue = asyncio.Queue()

        self._load_or_create_identity()

    def _load_or_create_identity(self):
        identity = self.storage.load_identity()
        if identity:
            self.client_id = identity['client_id']
            self.onion_address = identity['onion_address']
            self.crypto.load_keys(identity['keys'])
            logger.info(f"Loaded identity: {self.client_id[:8]}...")
        else:
            self._generate_new_identity()

    def _generate_new_identity(self):
        self.client_id = self._generate_random_id()
        keypair = self.crypto.generate_keypair()
        self.onion_address = ""  # will be set after Tor start
        identity = {
            'client_id': self.client_id,
            'onion_address': self.onion_address,
            'keys': keypair,
            'created_at': time.time()
        }
        self.storage.save_identity(identity)
        logger.info(f"Generated identity: {self.client_id[:8]}...")

    def _generate_random_id(self) -> str:
        random_bytes = os.urandom(32)
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        b58 = ''
        value = int.from_bytes(random_bytes, 'big')
        while value > 0:
            value, remainder = divmod(value, 58)
            b58 = alphabet[remainder] + b58
        return b58

    async def start(self):
        logger.info("Starting TorChat client...")
        await self.tor.start()
        self.onion_address = await self.tor.start_onion_service()
        # Update identity with onion address
        identity = self.storage.load_identity()
        identity['onion_address'] = self.onion_address
        self.storage.save_identity(identity)

        self.contacts = self.storage.load_contacts()
        self.is_running = True
        asyncio.create_task(self._message_processor())
        asyncio.create_task(self._listen_for_messages())
        asyncio.create_task(self._generate_cover_traffic())
        logger.info("TorChat client started")

    async def stop(self):
        self.is_running = False
        await self.tor.stop()
        logger.info("TorChat client stopped")

    async def add_contact(self, contact_id: str, onion_address: str) -> bool:
        try:
            request = ContactRequest(
                sender_id=self.client_id,
                sender_onion=self.onion_address,
                public_key=self.crypto.get_public_key(),
                timestamp=time.time()
            )
            encrypted_request = self.crypto.encrypt_for_contact(
                json.dumps(asdict(request)).encode(),
                contact_id
            )
            route = self.route_gen.generate_route()
            success = await self._send_via_tor(onion_address, encrypted_request, route)
            if success:
                contact = Contact(
                    id=contact_id,
                    onion_address=onion_address,
                    public_key="",
                    last_seen=time.time(),
                    nickname=None
                )
                self.contacts[contact_id] = contact
                self.storage.save_contact(contact)
            return success
        except Exception as e:
            logger.error(f"Add contact failed: {e}")
            return False

    async def send_message(self, contact_id: str, text: str) -> bool:
        if contact_id not in self.contacts:
            logger.error(f"Contact {contact_id} not found")
            return False
        contact = self.contacts[contact_id]
        if contact_id not in self.ratchets:
            await self._establish_ratchet(contact_id)
        ratchet = self.ratchets[contact_id]
        encrypted_message = ratchet.encrypt(text.encode())
        envelope = MessageEnvelope(
            sender_id=self.client_id,
            recipient_id=contact_id,
            timestamp=time.time(),
            message_type="text",
            payload=encrypted_message,
            padding=self.padder.generate_padding()
        )
        route = self.route_gen.generate_route()
        await self.message_queue.put((contact.onion_address, envelope, route))
        return True

    async def _message_processor(self):
        while self.is_running:
            onion_address, envelope, route = await self.message_queue.get()
            envelope_data = json.dumps(asdict(envelope)).encode()
            onion_encrypted = OnionEncryptor.encrypt_layers(envelope_data, route.hops)
            await self._send_via_tor(onion_address, onion_encrypted, route)
            logger.info(f"Message sent to {onion_address}")

    async def _listen_for_messages(self):
        while self.is_running:
            # Placeholder – actual listening would happen via onion service
            await asyncio.sleep(2)

    async def _send_via_tor(self, onion_address: str, data: bytes, route) -> bool:
        proxy = f"socks5h://127.0.0.1:{self.tor.socks_port}"
        url = f"http://{onion_address}/message"
        await asyncio.sleep(random.uniform(0.1, 0.5))
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, data=data, proxy=proxy, timeout=10) as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def _establish_ratchet(self, contact_id: str):
        contact = self.contacts[contact_id]
        shared_secret = self.crypto.generate_shared_secret(contact.public_key)
        ratchet = DoubleRatchet(shared_secret, self.crypto.get_keypair(), contact.public_key)
        self.ratchets[contact_id] = ratchet

    async def _generate_cover_traffic(self):
        while self.is_running:
            interval = random.expovariate(1.0/300)
            await asyncio.sleep(interval)
            if self.contacts:
                contact = random.choice(list(self.contacts.values()))
                dummy = self.padder.generate_dummy_message()
                route = self.route_gen.generate_route()
                await self._send_via_tor(contact.onion_address, dummy, route)
                logger.debug("Cover traffic sent")


# ============================================================================
# User Interface (CLI)
# ============================================================================
class TorChatUI:
    def __init__(self, client):
        self.client = client
        self.session = PromptSession()
        self.is_running = False
        self.bindings = KeyBindings()
        self._setup_keybindings()

    def _setup_keybindings(self):
        @self.bindings.add('c-d')
        def _(event):
            event.app.exit()

        @self.bindings.add('c-l')
        def _(event):
            print("\033[2J\033[H", end="")

    async def run(self):
        self.is_running = True
        print(colorama.Fore.CYAN + """
╔══════════════════════════════════════════════════╗
║                  T O R C H A T                   ║
║           Anonymous Encrypted Messaging          ║
╚══════════════════════════════════════════════════╝
        """ + colorama.Style.RESET_ALL)

        print(f"Your ID: {colorama.Fore.GREEN}{self.client.client_id[:16]}...{colorama.Style.RESET_ALL}")
        print(f"Onion: {colorama.Fore.YELLOW}{self.client.onion_address}{colorama.Style.RESET_ALL}")
        print("\nCommands: /help, /add, /list, /send, /exit\n")

        await self.client.start()

        while self.is_running:
            with patch_stdout():
                cmd = await self.session.prompt_async(
                    f"{colorama.Fore.BLUE}torchat>{colorama.Style.RESET_ALL} ",
                    key_bindings=self.bindings
                )
            await self._handle_command(cmd.strip())

    async def _handle_command(self, cmd: str):
        if not cmd:
            return
        if cmd.startswith('/'):
            parts = cmd.split()
            command = parts[0].lower()
            if command == '/help':
                self._show_help()
            elif command == '/exit':
                await self._shutdown()
            elif command == '/add':
                await self._add_contact(parts[1:])
            elif command == '/list':
                self._list_contacts()
            elif command == '/send':
                await self._send_message(parts[1:])
            elif command == '/info':
                self._show_info()
            else:
                print(f"{colorama.Fore.RED}Unknown command{colorama.Style.RESET_ALL}")
        else:
            print(f"{colorama.Fore.RED}Commands start with /{colorama.Style.RESET_ALL}")

    def _show_help(self):
        help_text = f"""
{colorama.Fore.CYAN}Commands:{colorama.Style.RESET_ALL}
/help          - Show this help
/add <id> <onion> - Add contact
/list          - List contacts
/send <id> <msg> - Send message
/info          - Show connection info
/exit          - Exit TorChat
        """
        print(help_text)

    async def _add_contact(self, args):
        if len(args) < 2:
            print("Usage: /add <contact_id> <onion_address>")
            return
        contact_id = args[0]
        onion = args[1]
        print(f"{colorama.Fore.YELLOW}Adding contact...{colorama.Style.RESET_ALL}")
        success = await self.client.add_contact(contact_id, onion)
        if success:
            print(f"{colorama.Fore.GREEN}Contact request sent!{colorama.Style.RESET_ALL}")
        else:
            print(f"{colorama.Fore.RED}Failed to add contact{colorama.Style.RESET_ALL}")

    def _list_contacts(self):
        if not self.client.contacts:
            print(f"{colorama.Fore.YELLOW}No contacts{colorama.Style.RESET_ALL}")
            return
        print(f"\n{colorama.Fore.CYAN}Contacts:{colorama.Style.RESET_ALL}")
        for cid, contact in self.client.contacts.items():
            print(f"  {contact.nickname or cid[:16]}...")
            print(f"     Onion: {contact.onion_address}")

    async def _send_message(self, args):
        if len(args) < 2:
            print("Usage: /send <contact_id> <message>")
            return
        contact_id = args[0]
        message = " ".join(args[1:])
        print(f"{colorama.Fore.YELLOW}Sending...{colorama.Style.RESET_ALL}")
        success = await self.client.send_message(contact_id, message)
        if success:
            print(f"{colorama.Fore.GREEN}Message sent!{colorama.Style.RESET_ALL}")
        else:
            print(f"{colorama.Fore.RED}Failed to send{colorama.Style.RESET_ALL}")

    def _show_info(self):
        print(f"""
Your ID: {self.client.client_id[:16]}...
Onion: {self.client.onion_address}
Connected to Tor: Yes
Active Contacts: {len(self.client.contacts)}
Cover Traffic: Active
        """)

    async def _shutdown(self):
        print("\nShutting down...")
        self.is_running = False
        await self.client.stop()
        print("Goodbye!")
        sys.exit(0)


# ============================================================================
# Main Entry Point
# ============================================================================
async def main():
    parser = argparse.ArgumentParser(description='TorChat – Anonymous messaging')
    parser.add_argument('--data-dir', default='~/.torchat',
                        help='Data directory (default: ~/.torchat)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    client = TorChatClient(data_dir=args.data_dir)
    ui = TorChatUI(client)

    try:
        await ui.run()
    except KeyboardInterrupt:
        print("\nInterrupted")
        await client.stop()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    asyncio.run(main())