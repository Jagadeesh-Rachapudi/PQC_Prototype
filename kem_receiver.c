#include <stdio.h>
#include <oqs/oqs.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#define PORT 9090

void printBytes(uint8_t *key, size_t length, const char *s) {
    printf("%s: ", s);
    for (size_t i = 0; i < length; i++) {
        printf("%02X", key[i]);
    }
    printf("\n");
}

void handleErrors() {
    printf("An error occurred.\n");
    exit(1);
}

void send_public_key(int socket, uint8_t *public_key, size_t length) {
    ssize_t bytes_sent = send(socket, public_key, length, 0);
    if (bytes_sent != length) {
        printf("Failed to send the full public key\n");
        close(socket);
        exit(1);
    }
    printf("Public key sent to sender.\n");
}

void receive_kem_ciphertext(int socket, uint8_t *ciphertext, size_t length) {
    ssize_t bytes_received = read(socket, ciphertext, length);
    if (bytes_received <= 0) {
        printf("Error or connection closed while receiving ciphertext\n");
        close(socket);
        exit(1);
    }
    if (bytes_received != length) {
        printf("Failed to receive full ciphertext, received only %ld bytes\n", bytes_received);
        close(socket);
        return;
    }
}

void aes_decrypt(const uint8_t *key, const unsigned char *ciphertext, int ciphertext_len, unsigned char **plaintext, int *plaintext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int block_size = 16;
    *plaintext = (unsigned char *)malloc(ciphertext_len + block_size);
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL))
        handleErrors();
    if (1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    *plaintext_len = len;
    if (1 != EVP_DecryptFinal_ex(ctx, *plaintext + len, &len))
        handleErrors();
    *plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    int server_fd, new_socket ,ns;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    int aes_cipher_size=0;
    uint8_t *received_aes_ciphertext = NULL;
    size_t received_aes_ciphertext_len;

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        printf("Socket failed\n");
        exit(1);
    }

    // Bind the socket to the port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1"); 
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        printf("Bind failed\n");
        exit(1);
    }

    if (listen(server_fd, 3) < 0) {
        printf("Listen failed\n");
        exit(1);
    }

    // Accept the connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
        printf("Accept failed\n");
        exit(1);
    }
    ns=new_socket;
    // Initialize the ML-KEM-512 algorithm
    OQS_KEM *kem = OQS_KEM_new("ML-KEM-512");

    if (kem == NULL) {
        printf("Failed to initialize ML-KEM-512\n");
        return 1;
    }

    uint8_t public_key[kem->length_public_key];
    uint8_t secret_key[kem->length_secret_key];

    // Generate keypair (public and secret keys)
    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        printf("Failed to generate keypair\n");
        OQS_KEM_free(kem);
        close(new_socket);
        return 1;
    }
    send_public_key(new_socket, public_key, kem->length_public_key);

    // Allocate space for ciphertext and shared secret
    uint8_t ciphertext[kem->length_ciphertext];
    uint8_t shared_secret_dec[kem->length_shared_secret];

    // Receive the ciphertext from the sender
    receive_kem_ciphertext(new_socket, ciphertext, kem->length_ciphertext);

    // Decapsulate the shared secret using the secret key
    if (OQS_KEM_decaps(kem, shared_secret_dec, ciphertext, secret_key) != OQS_SUCCESS) {
        printf("Failed to decapsulate shared secret\n");
        OQS_KEM_free(kem);
        close(new_socket);
        return 1;
    }

    // Print the shared secret on the receiver's side
    printf("Shared secret on receiver's side: ");
    for (size_t i = 0; i < kem->length_shared_secret; i++) {
        printf("%02X", shared_secret_dec[i]);
    }
    printf("\n");

    printf("%ld",kem->length_shared_secret);

    // Clean up and close
    OQS_KEM_free(kem);
    close(new_socket);
    close(server_fd);
    return 0;
}
