/*
 * OpenVPN XOR Scramble Implementation
 * Source file for XOR-based traffic obfuscation
 * Implements Tunnelblick XOR patch logic for compatibility
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"
#include "scramble.h"

#include <string.h>
#include <stdlib.h>

/*
 * Initialize scramble configuration from method string and key
 */
int
scramble_init(struct scramble_config *config, const char *method, const char *key)
{
    if (!config)
    {
        return -1;
    }

    memset(config, 0, sizeof(*config));

    if (!method || strlen(method) == 0)
    {
        config->method = SCRAMBLE_NONE;
        config->enabled = 0;
        return 0;
    }

    if (strcmp(method, "xormask") == 0 || strcmp(method, "xor_mask") == 0)
    {
        config->method = SCRAMBLE_XOR;
    }
    else if (strcmp(method, "xorptrpos") == 0 || strcmp(method, "xor_ptr") == 0)
    {
        config->method = SCRAMBLE_XOR_PTR;
    }
    else if (strcmp(method, "reverse") == 0)
    {
        config->method = SCRAMBLE_REVERSE;
    }
    else if (strcmp(method, "obfuscate") == 0)
    {
        config->method = SCRAMBLE_OBFUSCATE;
    }
    else
    {
        /* Default to XOR if method is unrecognized but key is provided */
        config->method = SCRAMBLE_XOR;
    }

    if (key && strlen(key) > 0)
    {
        size_t key_len = strlen(key);
        if (key_len >= SCRAMBLE_MAX_KEY_LEN)
        {
            key_len = SCRAMBLE_MAX_KEY_LEN - 1;
        }
        memcpy(config->key, key, key_len);
        config->key[key_len] = '\0';
        config->key_len = key_len;
    }
    else if (config->method == SCRAMBLE_XOR || config->method == SCRAMBLE_OBFUSCATE)
    {
        /* XOR methods require a key */
        return -1;
    }

    config->enabled = 1;
    return 0;
}

/*
 * Apply XOR mask to buffer using the provided key
 * Matches Tunnelblick buffer_mask
 */
void
buffer_mask(uint8_t *buf, size_t len, const char *key, size_t key_len)
{
    size_t i;

    if (!buf || len == 0 || !key || key_len == 0)
    {
        return;
    }

    for (i = 0; i < len; i++)
    {
        buf[i] ^= (uint8_t)key[i % key_len];
    }
}

/*
 * Reverse bytes in buffer, skipping the first byte
 * Matches Tunnelblick buffer_reverse
 */
void
buffer_reverse(uint8_t *buf, size_t len)
{
    size_t i;
    uint8_t *b_start;
    uint8_t *b_end;
    uint8_t temp;

    if (!buf || len <= 2)
    {
        /* Leave '', 'a', and 'ab' alone */
        return;
    }

    b_start = buf + 1;            /* point to first byte to swap */
    b_end   = buf + (len - 1);    /* point to last byte to swap */

    for (i = 0; i < (len - 1) / 2; i++, b_start++, b_end--)
    {
        temp = *b_start;
        *b_start = *b_end;
        *b_end = temp;
    }
}

/*
 * XOR each byte with its position in the packet
 * Matches Tunnelblick buffer_xorptrpos
 */
void
buffer_xorptrpos(uint8_t *buf, size_t len)
{
    size_t i;

    if (!buf || len == 0)
    {
        return;
    }

    for (i = 0; i < len; i++)
    {
        buf[i] ^= (uint8_t)(i + 1);
    }
}

/*
 * Scramble outgoing packet before sending
 */
ssize_t
scramble_outgoing(struct scramble_config *config, uint8_t *buf, ssize_t len)
{
    if (!config || !config->enabled || !buf || len <= 0)
    {
        return len;
    }

    switch (config->method)
    {
        case SCRAMBLE_XOR: /* xormethod = 1 */
            buffer_mask(buf, (size_t)len, config->key, config->key_len);
            break;

        case SCRAMBLE_XOR_PTR: /* xormethod = 2 */
            buffer_xorptrpos(buf, (size_t)len);
            break;

        case SCRAMBLE_REVERSE: /* xormethod = 3 */
            buffer_reverse(buf, (size_t)len);
            break;

        case SCRAMBLE_OBFUSCATE: /* xormethod = 4 */
            /* Tunnelblick Outgoing: XORPtr -> Reverse -> XORPtr -> Mask */
            buffer_xorptrpos(buf, (size_t)len);
            buffer_reverse(buf, (size_t)len);
            buffer_xorptrpos(buf, (size_t)len);
            buffer_mask(buf, (size_t)len, config->key, config->key_len);
            break;

        case SCRAMBLE_NONE:
        default:
            break;
    }

    return len;
}

/*
 * Unscramble incoming packet after receiving
 */
ssize_t
scramble_incoming(struct scramble_config *config, uint8_t *buf, ssize_t len)
{
    if (!config || !config->enabled || !buf || len <= 0)
    {
        return len;
    }

    switch (config->method)
    {
        case SCRAMBLE_XOR: /* xormethod = 1 */
            buffer_mask(buf, (size_t)len, config->key, config->key_len);
            break;

        case SCRAMBLE_XOR_PTR: /* xormethod = 2 */
            buffer_xorptrpos(buf, (size_t)len);
            break;

        case SCRAMBLE_REVERSE: /* xormethod = 3 */
            buffer_reverse(buf, (size_t)len);
            break;

        case SCRAMBLE_OBFUSCATE: /* xormethod = 4 */
            /* Tunnelblick Incoming: Mask -> XORPtr -> Reverse -> XORPtr */
            buffer_mask(buf, (size_t)len, config->key, config->key_len);
            buffer_xorptrpos(buf, (size_t)len);
            buffer_reverse(buf, (size_t)len);
            buffer_xorptrpos(buf, (size_t)len);
            break;

        case SCRAMBLE_NONE:
        default:
            break;
    }

    return len;
}

/*
 * Cleanup scramble configuration
 */
void
scramble_cleanup(struct scramble_config *config)
{
    if (config)
    {
        /* Securely clear the key from memory */
        memset(config->key, 0, sizeof(config->key));
        config->key_len = 0;
        config->enabled = 0;
        config->method = SCRAMBLE_NONE;
    }
}
