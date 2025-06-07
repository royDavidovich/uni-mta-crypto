#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>

#include "cipher_manager.h"
#include "mta_crypt.h"
#include "mta_rand.h"


// Helper: allocate and generate printable password

static void mta_generate_printable(char *buffer, int len)
{
    for (int i = 0; i < len; i++)
    {
        char c;
        do {
            c = MTA_get_rand_char();
        } while (!isprint((unsigned char)c));
        buffer[i] = c;
    }
}

static char *generate_printable_password(size_t len)
{
    char *buf = malloc(len);
    if (!buf) {
        fprintf(stderr, "malloc(plaintext) failed\n");
        exit(EXIT_FAILURE);
    }
    mta_generate_printable(buf, len);
    return buf;
}

// Helper: allocate and generate random key
static unsigned char *generate_random_key(size_t len_bytes)
{
    unsigned char *key = malloc(len_bytes);
    if (!key) {
        fprintf(stderr, "malloc(key) failed\n");
        exit(EXIT_FAILURE);
    }
    MTA_get_rand_data(key, len_bytes);
    return key;
}

// Helper: encrypt plaintext with key, returns encrypted buffer (malloced)
static char *encrypt_password(char *plaintext, size_t plaintext_len,
                                       const char *key, size_t key_len,
                                       size_t *out_encrypted_len)
{
    char *encrypted = malloc(plaintext_len);
    if (!encrypted) {
        fprintf(stderr, "malloc(encrypted) failed\n");
        exit(EXIT_FAILURE);
    }
    unsigned int out_len = (unsigned int)plaintext_len;
    int st = MTA_encrypt((char *)key, (unsigned int)key_len,
                         plaintext, (unsigned int)plaintext_len,
                         (char *)encrypted, &out_len);
    if (st != MTA_CRYPT_RET_OK) {
        fprintf(stderr, "MTA_encrypt error: %d\n", st);
        exit(EXIT_FAILURE);
    }
    *out_encrypted_len = out_len;
    return encrypted;
}


// Helper: print password or candidate with escapes for non-printable chars
static void print_escaped(const unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char c = buf[i];
        if (isprint(c) && c != '\\' && c != '\"') {
            putchar(c);
        } else {
            printf("\\x%02X", c);
        }
    }
}

static void log_new_password_info(const char *plaintext,
                                  const unsigned char *key,
                                  size_t key_len_bytes,
                                  const unsigned char *encrypted,
                                  size_t encrypted_len)
{
    long ts = get_unix_timestamp_seconds();
    printf("%ld [ENCRYPTER] [INFO] New password generated: \"", ts);
    print_escaped((const unsigned char *)plaintext, g_password_len);
    printf("\", key (hex): ");
    hex_escape_and_print(key, key_len_bytes, 16);
    printf(", encrypted (hex): ");
    hex_escape_and_print(encrypted, encrypted_len, 16);
    printf("\n");
}

// Helper: wait for crack signal or timeout
static void wait_for_crack_or_timeout(void)
{
    if (g_timeout_secs > 0) {
        struct timespec now, deadline;
        clock_gettime(CLOCK_REALTIME, &now);
        deadline.tv_sec = now.tv_sec + g_timeout_secs;
        deadline.tv_nsec = now.tv_nsec;

        pthread_mutex_lock(&g_mutex);
        while (!g_password_cracked) {
            int rc = pthread_cond_timedwait(&g_new_cipher_cond, &g_mutex, &deadline);
            if (rc == ETIMEDOUT) {
                long t2 = get_unix_timestamp_seconds();
                printf("%ld [ENCRYPTER] [INFO] Timeout expired after %d seconds; generating new password.\n",
                       t2, g_timeout_secs);
                break;
            }
        }
        pthread_mutex_unlock(&g_mutex);
    } else {
        pthread_mutex_lock(&g_mutex);
        while (!g_password_cracked) {
            pthread_cond_wait(&g_new_cipher_cond, &g_mutex);
        }
        pthread_mutex_unlock(&g_mutex);
    }
}



// Main encrypter thread function
void *encrypter_thread_fn(void *arg)
{
    (void)arg;

    while (1)
    {
        // 1 & 2: Generate password and key
        char *plaintext = generate_printable_password(g_password_len);
        int key_len_bytes = g_password_len / 8;
        unsigned char *key = generate_random_key(key_len_bytes);

        // 3: Encrypt
        size_t encrypted_len;
        unsigned char *encrypted = encrypt_password(plaintext, g_password_len, key, key_len_bytes, &encrypted_len);

        log_new_password_info(plaintext, key, key_len_bytes, encrypted, encrypted_len);

        // 5: Publish ciphertext and broadcast
        pthread_mutex_lock(&g_mutex);
        free(g_ciphertext);
        g_ciphertext = encrypted;
        g_ciphertext_len = encrypted_len;
        g_password_cracked = 0;
        pthread_cond_broadcast(&g_new_cipher_cond);
        pthread_mutex_unlock(&g_mutex);

        // 6: Wait for crack or timeout
        wait_for_crack_or_timeout();

        // 7: If cracked, log info about who cracked it and plaintext candidate

        // TODO add check for wrong password
        if (g_password_cracked) {
            long t3 = get_unix_timestamp_seconds();
            printf("%ld [ENCRYPTER] [OK] Password decrypted successfully by %s, plaintext: \"",
                   t3, (char *)g_plaintext_candidate);
            print_escaped((unsigned char *)g_plaintext_candidate, g_password_len);
            printf("\"\n");
        }

        // 8: Clean up buffers
        free(plaintext);
        free(key);

        // Loop continues for next password
    }

    return NULL; // never reached
}
