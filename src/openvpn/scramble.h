/*
 * OpenVPN XOR Scramble Implementation
 * Header file for XOR-based traffic obfuscation
 */

#ifndef OPENVPN_SCRAMBLE_H
#define OPENVPN_SCRAMBLE_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/types.h>
#endif

/* Maximum scramble key length */
#define SCRAMBLE_MAX_KEY_LEN 256

/* Scramble method types */
typedef enum {
    SCRAMBLE_NONE = 0,
    SCRAMBLE_XOR,
    SCRAMBLE_XOR_PTR,
    SCRAMBLE_REVERSE,
    SCRAMBLE_OBFUSCATE
} scramble_method_t;

/* Scramble configuration structure */
struct scramble_config {
    scramble_method_t method;
    char key[SCRAMBLE_MAX_KEY_LEN];
    size_t key_len;
    int enabled;
};

/*
 * Initialize scramble configuration
 * Returns 0 on success, -1 on failure
 */
int scramble_init(struct scramble_config *config, const char *method, const char *key);

/*
 * Apply XOR mask to buffer
 * Performs in-place XOR operation on the buffer using the key
 */
void buffer_mask(uint8_t *buf, size_t len, const char *key, size_t key_len);

/*
 * Scramble outgoing packet
 * Call this before sending data over the socket
 * Returns the (potentially modified) length of data to send
 */
ssize_t scramble_outgoing(struct scramble_config *config, uint8_t *buf, ssize_t len);

/*
 * Unscramble incoming packet
 * Call this after receiving data from the socket
 * Returns the (potentially modified) length of received data
 */
ssize_t scramble_incoming(struct scramble_config *config, uint8_t *buf, ssize_t len);

/*
 * Reverse bytes in buffer
 * Used for SCRAMBLE_REVERSE and SCRAMBLE_OBFUSCATE methods
 */
void buffer_reverse(uint8_t *buf, size_t len);

/*
 * XOR with pointer offset method
 * XORs each byte with its position in the packet
 */
void buffer_xorptrpos(uint8_t *buf, size_t len);

/*
 * Cleanup scramble configuration
 */
void scramble_cleanup(struct scramble_config *config);

#endif /* OPENVPN_SCRAMBLE_H */
