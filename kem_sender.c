#include <stdio.h>
#include <oqs/oqs.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>

#define PORT 9090

void print_public_key(uint8_t *key, size_t length) {
    printf("Sender received public key: ");
    for (size_t i = 0; i < length; i++) {
        printf("%02X", key[i]);
    }
    printf("\n");
}

// Function to receive public key from the receiver
void receive_public_key(int socket, uint8_t *public_key, size_t length) {
    ssize_t bytes_received = read(socket, public_key, length);
    if (bytes_received != length) {
        printf("Failed to receive the full public key\n");
        close(socket);
        exit(1);
    }
}

// Function to send ciphertext over a network using an already connected socket
void send_ciphertext(int socket, uint8_t *ciphertext, size_t length) {
    ssize_t bytes_sent = send(socket, ciphertext, length, 0);
    printf("%ld The lenght",length);
    if (bytes_sent != length) {
        printf("Failed to send the full ciphertext\n");
        close(socket);  // Only close the socket if you don't plan to reuse it later
        exit(1);
    }
    printf("Ciphertext sent to receiver.\n");
    // print_public_key(ciphertext,length);
}

int main() {
    int sock;
    struct sockaddr_in serv_addr;

    string s = "Iam Jagadeesh";

    OQS_KEM *kem = OQS_KEM_new("ML-KEM-512");

    if (kem == NULL) {
        printf("Failed to initialize ML-KEM-512\n");
        return 1;
    }

    uint8_t public_key[kem->length_public_key];
    uint8_t secret_key[kem->length_secret_key];
    uint8_t ciphertext[kem->length_ciphertext];
    uint8_t shared_secret_enc[kem->length_shared_secret];

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Socket creation error\n");
        OQS_KEM_free(kem);
        return 1;
    }

    // Set server address
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Assuming the receiver is on localhost
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("Invalid address\n");
        close(sock);
        OQS_KEM_free(kem);
        return 1;
    }

    // Connect to the receiver
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("Connection failed\n");
        close(sock);
        OQS_KEM_free(kem);
        return 1;
    }

    // Receive the public key from the receiver
    receive_public_key(sock, public_key, kem->length_public_key);

    // Encypt the shared key
    if (OQS_KEM_encaps(kem, ciphertext, shared_secret_enc, public_key) != OQS_SUCCESS) {
        printf("Failed to encapsulate shared secret\n");
        close(sock);
        OQS_KEM_free(kem);
        return 1;
    }

    // Print the shared secret on the sender's side
    printf("Shared secret on sender's side: ");
    for (size_t i = 0; i < kem->length_shared_secret; i++) {
        printf("%02X", shared_secret_enc[i]);
    }
    printf("\n");

    // Send the ciphertext (encapsulated key) to the receiver
    send_ciphertext(sock, ciphertext, kem->length_ciphertext);

    // Free resources
    close(sock);
    OQS_KEM_free(kem);

    return 0;

}
