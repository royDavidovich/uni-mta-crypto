//
// Created by parallels on 6/7/25.
//

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include <pthread.h>
#include <sys/time.h>    // for struct timeval / struct itimerspec
#include <time.h>        // for clock_gettime(), struct timespec
#include <errno.h>
#include <ctype.h>       // for isprint()
//

#include <mta_rand.h>
#include <mta_crypt.h>
#include "encryptor.h"
#include "mta_crypto.h"

/* ────────────────────────────────────────────────────────────────────────── */
/* Encrypter thread: generate printable password, generate random key, encrypt */
/* via MTA_encrypt(), then broadcast to all decrypters.                       */
/* ────────────────────────────────────────────────────────────────────────── */
void *encrypter_thread_fn(void *arg)
{
    (void)arg;
    char *plaintext = NULL;
    char *key       = NULL;

    while (1)
    {
        // 1) Generate a new printable password of length g_password_len
        plaintext = malloc(g_password_len);
        if (!plaintext) {
            fprintf(stderr, "malloc(plaintext) failed\n");
            exit(EXIT_FAILURE);
        }
        mta_generate_printable((char *)plaintext, g_password_len);

        // 2) Generate a random key of length = (g_password_len / 8) bytes
        int key_len_bytes = g_password_len / 8;
        key = (unsigned char *)malloc(key_len_bytes);
        if (!key) {
            fprintf(stderr, "malloc(key) failed\n");
            exit(EXIT_FAILURE);
        }

        MTA_get_rand_data(key, key_len_bytes);

        // 3) Encrypt via MTA_encrypt (RC2-ECB). encrypted_len = g_password_len
        size_t encrypted_len = g_password_len;
        unsigned char *encrypted = malloc(encrypted_len);
        if (!encrypted) {
            fprintf(stderr, "malloc(encrypted) failed\n");
            exit(EXIT_FAILURE);
        }
        unsigned int out_len = (unsigned int)encrypted_len;
        MTA_CRYPT_RET_STATUS st = MTA_encrypt(
            (char *)key,
            (unsigned int)key_len_bytes,
            (char *)plaintext,
            (unsigned int)g_password_len,
            (char *)encrypted,
            &out_len
        );
        if (st != MTA_CRYPT_RET_OK) {
            fprintf(stderr, "MTA_encrypt error: %d\n", st);
            exit(EXIT_FAILURE);
        }

        // 4) Log “New password generated”
        long ts = get_unix_timestamp_seconds();
        printf("%ld [ENCRYPTER] [INFO] New password generated: \"", ts);
        // Print the plaintext itself (raw printable chars), with “\” escapes for hidden bytes
        for (int i = 0; i < g_password_len; i++) {
            unsigned char c = plaintext[i];
            if (isprint(c) && c != '\\' && c != '\"') {
                putchar(c);
            } else {
                // Print non‐printable or “\” or “"” as \xHH
                printf("\\x%02X", c);
            }
        }
        printf("\", key (hex): ");
        hex_escape_and_print(key, key_len_bytes, 16);
        printf(", encrypted (hex): ");
        hex_escape_and_print(encrypted, encrypted_len, 16);
        printf("\n");

        // 5) Publish the ciphertext under the mutex and broadcast
        pthread_mutex_lock(&g_mutex);
        free(g_ciphertext);
        g_ciphertext = encrypted;
        g_ciphertext_len = encrypted_len;
        g_password_cracked = 0;  // reset cracked‐flag
        pthread_cond_broadcast(&g_new_cipher_cond);
        pthread_mutex_unlock(&g_mutex);

        // 6) Wait for either a crack or timeout
        if (g_timeout_secs > 0) {
            struct timespec now, deadline;
            clock_gettime(CLOCK_REALTIME, &now);
            deadline.tv_sec  = now.tv_sec + g_timeout_secs;
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
        }
        else {
            pthread_mutex_lock(&g_mutex);
            while (!g_password_cracked) {
                pthread_cond_wait(&g_new_cipher_cond, &g_mutex);
            }
            pthread_mutex_unlock(&g_mutex);
        }

        // 7) If cracked, log which client cracked it
        if (g_password_cracked) {
            long t3 = get_unix_timestamp_seconds();

            printf("%ld [ENCRYPTER] [OK] Password decrypted successfully by %s, plaintext: \"",
                   t3,
                   /* We assume g_plaintext_candidate was set by the winning client with a global tag like "CLIENT #k" */
                   (char *)g_plaintext_candidate /* placeholder—see note below */);
            // Actually, to know which client it was, you should have stored the client‐ID in g_plaintext_candidate or in another shared variable.
            // For simplicity, we assume that g_plaintext_candidate prefixed itself with "CLIENT #k:". If not, you can modify the client code to write "CLIENT #k:<plaintext>".
            // Here we simply print g_plaintext_candidate as raw bytes:
            for (int i = 0; i < g_password_len; i++) {
                unsigned char c = ((unsigned char *)g_plaintext_candidate)[i];
                if (isprint(c) && c != '\\' && c != '\"') {
                    putchar(c);
                } else {
                    printf("\\x%02X", c);
                }
            }
            printf("\"\n");
        }

        // 8) Free per‐round buffers (plaintext, key). ciphertext was already freed when overwritten next round
        free(plaintext);
        free(key);

        // Loop back for next password
    }

    return NULL; // never reached
}