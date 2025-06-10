#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <string.h>

#include "cipher_manager.h"
#include "mta_crypt.h"
#include "mta_rand.h"

struct timespec now, deadline;

// Helper: allocate and generate printable password
static void mta_generate_printable(char *buffer, int len)
{
    for (int i = 0; i < len; i++)
    {
        char c;

        do
        {
            c = MTA_get_rand_char();
        } while (!isprint((unsigned char)c));

        buffer[i] = c;
    }
}

static char *generate_printable_password(size_t len)
{
    char *buf = malloc(len);

    if (!buf)
    {
        fprintf(stderr, "malloc(plaintext) failed\n");
        exit(EXIT_FAILURE);
    }

    mta_generate_printable(buf, len);
    return buf;
}

// Helper: allocate and generate random key
static char *generate_random_key(size_t len_bytes)
{
    char *key = malloc(len_bytes);

    if (!key)
    {
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

    if (!encrypted)
    {
        fprintf(stderr, "malloc(encrypted) failed\n");
        exit(EXIT_FAILURE);
    }

    unsigned int out_len = (unsigned int)plaintext_len;
    int st = MTA_encrypt((char *)key, (unsigned int)key_len,
                         plaintext, (unsigned int)plaintext_len,
                         (char *)encrypted, &out_len);

    if (st != MTA_CRYPT_RET_OK)
    {
        fprintf(stderr, "MTA_encrypt error: %d\n", st);
        exit(EXIT_FAILURE);
    }

    *out_encrypted_len = out_len;
    return encrypted;
}

static void log_new_password_info(const char *plaintext,
                                  const char *key,
                                  size_t key_len_bytes)
{
    long ts = get_unix_timestamp_seconds();

    printf("%ld [ENCRYPTER]    [INFO] New password generated: \"", ts);
    print_escaped((const char *)plaintext, g_password_len);
    printf("\". sending to all decrypters. ");
    printf("Key (hex): ");
    hex_escape_and_print(key, key_len_bytes, 16);
    printf("\n");
}

// Helper: Updates deadline (relevant only when "-t" was asked)
static void update_deadline()
{
    clock_gettime(CLOCK_REALTIME, &now);
    deadline.tv_sec = now.tv_sec + g_timeout_secs;
    deadline.tv_nsec = now.tv_nsec;
}

// Helper: wait for crack signal or timeout
static void wait_for_crack_or_timeout(void)
{
    if (g_timeout_secs > 0)
    {
        pthread_mutex_lock(&g_mutex);
        int rc = pthread_cond_timedwait(&g_new_cipher_cond, &g_mutex, &deadline);
        if (rc == ETIMEDOUT)
        {
            long t2 = get_unix_timestamp_seconds();
            printf("%ld [ENCRYPTER]    [INFO] Timeout expired after %d seconds; generating new password.\n",
                   t2, g_timeout_secs);
            update_deadline();
        }
        pthread_mutex_unlock(&g_mutex);
    }
    else
    {
        pthread_mutex_lock(&g_mutex);
        pthread_cond_wait(&g_new_cipher_cond, &g_mutex);
        pthread_mutex_unlock(&g_mutex);
    }
}

// Main encrypter thread function
void *encrypter_thread_fn(void *arg)
{
    (void)arg;

    while (1)
    {
        char *plaintext = generate_printable_password(g_password_len);
        int key_len_bytes = g_password_len / 8;
        char *key = generate_random_key(key_len_bytes);

        size_t encrypted_len;
        char *encrypted = encrypt_password(plaintext, g_password_len, key, key_len_bytes, &encrypted_len);

        log_new_password_info(plaintext, key, key_len_bytes);

        pthread_mutex_lock(&g_mutex);
        g_ciphertext = encrypted;
        g_ciphertext_len = encrypted_len;
        g_password_cracked_or_timeout = 0;
        update_deadline();
        pthread_cond_broadcast(&g_new_cipher_cond);
        pthread_mutex_unlock(&g_mutex);

        while (g_password_cracked_or_timeout == 0)
        {
            wait_for_crack_or_timeout();
            pthread_mutex_lock(&g_mutex);
            long t3 = get_unix_timestamp_seconds();

            if (g_plaintext_candidate != NULL && strcmp(g_plaintext_candidate->guess, plaintext) != 0)
            {
                printf("%ld [ENCRYPTER]    [ERROR] Wrong password %s should be %s\n", t3, g_plaintext_candidate->guess, plaintext);
                pthread_mutex_unlock(&g_mutex);
                continue;
            }

            g_ciphertext = NULL;
            g_password_cracked_or_timeout = 1;
            if (g_plaintext_candidate != NULL)
            {
                printf("%ld [ENCRYPTER]    [OK]   Password decrypted successfully by [DECRYPTER #%ld], plaintext: \"",
                       t3, g_plaintext_candidate->id);
                print_escaped(g_plaintext_candidate->guess, g_password_len);
                printf("\"\n");
            }
            pthread_mutex_unlock(&g_mutex);
        }

        free(plaintext);
        free(key);
    }

    return NULL;
}