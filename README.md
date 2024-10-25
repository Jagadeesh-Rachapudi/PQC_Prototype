# Post-Quantum Cryptography KEM (Key Encapsulation Mechanism) Example

This repository demonstrates a simple Key Encapsulation Mechanism (KEM) example using a receiver and sender. The receiver first generates a public/private key pair, and the sender then uses the receiver's public key to securely send a shared key. This is implemented using the **liboqs** (Open Quantum Safe) library.

## Prerequisites

Make sure you have the **liboqs** library installed on your system. Follow the [Open Quantum Safe](https://openquantumsafe.org/liboqs/) documentation to install the library and its dependencies.

## Instructions

### Compile and Run the Programs

Follow these steps to compile and run both the receiver and sender:

```bash
# Step 1: Compile the Receiver
gcc receiver.c -o r -loqs -lcrypto

# Step 2: Compile the Sender
gcc sender.c -o s -loqs -lcrypto

# Step 3: Run the Receiver
./r

# Step 4: In a separate terminal, run the Sender
./s
```

