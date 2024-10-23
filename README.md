# PQC Prototype

This project demonstrates the use of Key Encapsulation Mechanism (KEM) for secure key exchange using the `kem_receiver.c` and `kem_sender.c` programs. The project utilizes Open Quantum Safe (OQS) libraries for post-quantum cryptographic techniques.

## Requirements

- GCC compiler
- Open Quantum Safe (OQS) library

Make sure the OQS library is installed on your system. You can find more information about OQS installation [here](https://github.com/open-quantum-safe/liboqs).

## Compilation Instructions

To compile and run the programs, follow these steps:

### Step 1: Compile the Receiver Program

To compile the receiver program, run the following command:

```bash
gcc kem_receiver.c -o kem_receiver -loqs
