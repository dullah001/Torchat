torchat

torchat is an anonymous, encrypted messaging application that routes all traffic through the Tor network. It provides strong privacy guarantees by hiding metadata, using the Signal Protocol for end-to-end encryption, and adding additional layers of anonymity through random circuit routing and cover traffic.

⚠️ IMPORTANT: This project is for educational purposes only and is NOT production-ready. Use at your own risk.


Features

· Full Tor integration: All connections forced through Tor; no clearnet leaks.
· End-to-end encryption: Based on the Signal Protocol (X3DH + Double Ratchet) for perfect forward secrecy.
· Anonymous identities: No phone numbers or emails required; each user gets a cryptographic ID and onion service address.
· Metadata protection: Messages padded to constant size, random delays, and optional cover traffic.
· Plausible deniability: Decoy conversations and panic wipe (conceptual).
· Single‑file CLI: Easy to run and modify – everything in one Python script.


Prerequisites

· Python 3.8+
· Tor (must be installed and in your PATH)
  · Debian/Ubuntu: sudo apt install tor
  · macOS: brew install tor
  · Windows: download from torproject.org


Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/dullah001/torchat.git
   cd torchat
   ```
2. Install Python dependencies:
   ```bash
   pip install stem cryptography aiohttp prompt-toolkit colorama
   ```
3. Make sure Tor is running (in a separate terminal or as a service):
   ```bash
   tor
   ```



Usage

Run the script:

```bash
python torchat.py
```

Optional arguments:

· --data-dir PATH – Set a custom data directory (default: ~/.torchat).
· --debug – Enable debug logging.

Available commands (inside the app):

Command Description
/help Show available commands
/add <id> <onion> Add a new contact
/list List all contacts
/send <id> <message> Send a message to a contact
/info Show connection and identity info
/exit Exit the application



Project Structure (single‑file)

All code is contained in torchat.py. The file includes:

· Tor controller and onion service management
· Signal Protocol cryptography
· Message envelope and ratchet logic
· CLI user interface
· Local encrypted storage



Security Considerations

torchat attempts to provide strong anonymity, but it has limitations:

· Traffic analysis: While cover traffic and padding help, a global adversary may still correlate timing.
· Endpoint compromise: If your device is compromised, all bets are off.
· Tor entry/exit nodes: Malicious Tor nodes could attempt to deanonymize users.
· Not audited: The code has not undergone a formal security audit.



License

This project is licensed under the MIT License – see the LICENSE file for details.



Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. The authors are not responsible for any misuse or damage caused by this software. Always comply with local laws and regulations.
