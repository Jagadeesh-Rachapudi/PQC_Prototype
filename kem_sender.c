#include <stdio.h>
#include <oqs/oqs.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
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

void receive_public_key(int socket, uint8_t *public_key, size_t length) {
    ssize_t bytes_received = read(socket, public_key, length);
    if (bytes_received != length) {
        printf("Failed to receive the full public key\n");
        close(socket);
        exit(1);
    }
    printf("Public key recived form receiver.\n");
}

// Function to send ciphertext over a network using an already connected socket
void send_kem_ciphertext(int socket, uint8_t *ciphertext, size_t length) {
    ssize_t bytes_sent = send(socket, ciphertext, length, 0);
    if (bytes_sent != length) {
        printf("Failed to send the full ciphertext\n");
        close(socket);
        exit(1);
    }
}

void send_aes_ciphertext(int socket, uint8_t *ciphertext, size_t length) {
    ssize_t bytes_sent = send(socket, ciphertext, length, 0);
    if (bytes_sent != length) {
        printf("Failed to send the full ciphertext\n");
        close(socket);
        exit(1);
    }
    printf("\nKEM Cipher sent to receiver.\n");
}

void handleErrors() {
    printf("An error occurred.\n");
    exit(1);
}

void aes_encrypt(const uint8_t *key, const unsigned char *plaintext, unsigned char **ciphertext, int *ciphertext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len = strlen((char *)plaintext);
    int block_size = 16;
    *ciphertext = (unsigned char *)malloc(block_size);
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL))
        handleErrors();
    *ciphertext = (unsigned char *)realloc(*ciphertext, (plaintext_len / block_size + 1) * block_size);
    if (1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    *ciphertext_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len))
        handleErrors();
    *ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
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
    int sock;
    struct sockaddr_in serv_addr;
    unsigned char plaintext[] = "Kajajjajajajaajjjjjjjjjjjj";
    unsigned char *encrypted_text = NULL;
    int encrypted_text_len;
    int AES_cipher_len;
    unsigned char *decrypted_text = NULL;  // This will hold the decrypted text
    int decrypted_text_len;

    OQS_KEM *kem = OQS_KEM_new("ML-KEM-512");

    if (kem == NULL) {
        printf("Failed to initialize ML-KEM-512\n");
        return 1;
    }

    uint8_t public_key[kem->length_public_key];
    uint8_t secret_key[kem->length_secret_key];
    uint8_t ciphertext[kem->length_ciphertext];
    uint8_t shared_secret_enc[kem->length_shared_secret];

    //Establishing connection
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Socket creation error\n");
        OQS_KEM_free(kem);
        return 1;
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("Invalid address\n");
        close(sock);
        OQS_KEM_free(kem);
        return 1;
    }
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
    printBytes(shared_secret_enc,kem->length_shared_secret,"Shared secret on sender's sideaaaaaaaaaaaaaa");
    
    // Send the ciphertext (encapsulated key) to the receiver
    send_kem_ciphertext(sock, ciphertext, kem->length_ciphertext);

    // Free resources
    close(sock);
    OQS_KEM_free(kem);

    return 0;

}
