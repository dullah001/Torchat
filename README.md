Torchat

Torchat is an anonymous, encrypted messaging application that routes all traffic through the Tor network. It provides strong privacy guarantees by hiding metadata, using the Signal Protocol for end-to-end encryption, and adding additional layers of anonymity through random circuit routing and cover traffic.

⚠️ IMPORTANT: This project is for educational purposes only and is NOT production-ready. Use at your own risk.


Features

· Complete Tor Integration: All traffic is forced through the Tor network; no clearnet connections.
· End-to-End Encryption: Based on the Signal Protocol (X3DH + Double Ratchet) for perfect forward secrecy.
· Anonymous Identities: No phone numbers or email required – each user gets a random cryptographic ID and an onion service address.
· Metadata Protection:
  · All messages are padded to a constant size.
  · Random delays between messages prevent timing analysis.
  · Cover traffic (dummy messages) further obscures real communication.
· Randomized Routing: Each message takes a different Tor circuit, randomly selected from available relays.
· Plausible Deniability: Optional decoy conversations and panic wipe functionality.
· Multiple Interfaces:
  · Terminal-based CLI with rich interaction (prompt_toolkit)
  · Modern graphical interface using Kivy (cross-platform)
· Distributed Directory: Contact discovery via a DHT (conceptual; not fully implemented).


Prerequisites

· Python 3.8+
· Tor (must be installed and in your PATH)
  · On Debian/Ubuntu: sudo apt install tor
  · On macOS: brew install tor
  · On Windows: download from torproject.org
· Git (to clone the repository)


Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/torsignal.git
   cd torsignal
   ```
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the setup script (optional, but recommended):
   ```bash
   python setup.py
   ```
   This will check for Tor, install Python packages, and create a desktop entry (Linux only).


Usage

Starting Tor

Before running TorSignal, make sure Tor is running. You can start it manually:

```bash
tor # or use your system's service manager
```

Terminal-Based CLI

Launch the terminal interface:

```bash
python -m torsignal
```

Once inside, you can use the following commands:

Command Description
/help Show available commands
/add <id> <onion> Add a new contact
/list List all contacts
/send <id> <message> Send a message to a contact
/info Show connection and identity info
/panic Emergency wipe (destroys all data)
/exit Exit the application

Kivy Graphical Interface

For a modern GUI experience, run:

```bash
python -m torsignal.gui.kivy_gui
```

The GUI provides:

· A contacts sidebar
· A chat area with scrollable message history
· A popup for adding contacts
· Real-time message display

Note: The Kivy GUI runs in its own thread; the client core runs in the background.


Configuration

TorSignal stores its data in ~/.torsignal/ by default. This directory contains:

· identity.json – Your cryptographic identity and keys.
· contacts.json – List of contacts and their onion addresses.
· settings.json – User preferences (future use).

You can change the data directory by passing --data-dir PATH when starting the CLI.

---

Project Structure

```
torsignal/
├── client/               # Core client logic
│   ├── core.py           # Main TorSignalClient class
│   ├── crypto.py         # Signal Protocol and onion encryption
│   ├── tor_manager.py    # Tor controller and circuit management
│   ├── storage.py        # Encrypted local storage
│   └── ui.py             # Terminal-based UI
├── gui/                  # Graphical interfaces
│   └── kivy_gui.py       # Kivy-based GUI
├── protocol/             # Message formats and ratchet logic
│   ├── messages.py       # Envelope and contact request definitions
│   └── ratchet.py        # Double Ratchet implementation
├── utils/                # Helper modules
│   ├── random_route.py   # Random circuit generation
│   └── padding.py        # Traffic padding and cover traffic
├── __main__.py           # CLI entry point
├── setup.py              # Setup wizard
└── requirements.txt      # Python dependencies
```


Security Considerations

TorSignal attempts to provide strong anonymity, but it has limitations:

· Traffic Analysis: While cover traffic and padding help, a global adversary may still correlate timing.
· Endpoint Compromise: If your device is compromised, all bets are off.
· Tor Entry/Exit Nodes: Malicious Tor nodes could attempt to deanonymize users.
· Not Audited: The code has not undergone a formal security audit; use it only for learning.

Threat Model

· Protected against: Passive network surveillance, metadata collection, censorship.
· Not protected against: Active global adversaries with unlimited resources, targeted malware.


Contributing

Contributions are welcome! If you'd like to help:

1. Fork the repository.
2. Create a feature branch.
3. Make your changes.
4. Submit a pull request.

Please follow the existing code style and include tests if applicable.

---

License

This project is licensed under the MIT License – see the LICENSE file for details.


Acknowledgments

· The Tor Project for providing the anonymity network.
· The Signal Protocol for its cryptographic foundations.
· The Kivy team for the cross-platform GUI framework.
· All contributors and testers.


⚠️Disclaimer⚠️

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. The authors are not responsible for any misuse or damage caused by this software. Always comply with local laws and regulations.
