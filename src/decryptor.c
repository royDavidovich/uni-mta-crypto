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
#include "cipher_manager.h"
#include "decryptor.h"

/* ────────────────────────────────────────────────────────────────────────── */
/* Decrypter thread: wait for g_ciphertext, then brute‐force keys until      */
/* we see “all bytes are printable.”  Once found, set g_password_cracked = 1.  */
/* ────────────────────────────────────────────────────────────────────────── */
void *decrypter_thread_fn(void *arg)
{
    long idx = (long)arg; // client‐ID (0,1,2,…)
    char *my_cipher_copy = NULL;
    size_t my_cipher_len = 0;

    while (1)
    {
        // 1) Wait for fresh ciphertext
        pthread_mutex_lock(&g_mutex);
        while (g_ciphertext == NULL) {
            pthread_cond_wait(&g_new_cipher_cond, &g_mutex);
        }
        my_cipher_len = g_ciphertext_len;

        my_cipher_copy = malloc(my_cipher_len);
        if (!my_cipher_copy) {
            fprintf(stderr, "malloc(my_cipher_copy) failed\n");
            exit(EXIT_FAILURE);
        }
        memcpy(my_cipher_copy, g_ciphertext, my_cipher_len);
        pthread_mutex_unlock(&g_mutex);

        // 2) Start brute‐force loop
        int key_len_bytes = (int)(my_cipher_len / 8);
        char *trial_key = malloc(key_len_bytes);
        char *decrypted = malloc(my_cipher_len);
        if (!trial_key || !decrypted) {
            fprintf(stderr, "malloc(trial_key/decrypted) failed\n");
            exit(EXIT_FAILURE);
        }

        long iterations = 0;
        long start_ts = get_unix_timestamp_seconds();
        printf("%ld [DECRYPTER #%ld] [INFO] Starting brute‐force on new ciphertext (len=%zu)...\n",
               start_ts, idx, my_cipher_len);

        while (1)
        {
            // (a) If already cracked by another client, exit this loop
            pthread_mutex_lock(&g_mutex);
            if (g_password_cracked) {
                pthread_mutex_unlock(&g_mutex);
                break;
            }
            pthread_mutex_unlock(&g_mutex);

            // (b) Generate a random key candidate
            MTA_get_rand_data(trial_key, key_len_bytes);

            // (c) Attempt decryption
            unsigned int out_len = (unsigned int)my_cipher_len;
            MTA_CRYPT_RET_STATUS st = MTA_decrypt(
                (char *)trial_key,
                (unsigned int)key_len_bytes,
                (char *)my_cipher_copy,
                (unsigned int)my_cipher_len,
                (char *)decrypted,
                &out_len
            );
            iterations++;
            if (st != MTA_CRYPT_RET_OK) {
                continue; // skip invalid decryption
            }

            // (d) Check if all bytes are printable
            int all_printable = 1;
            for (size_t i = 0; i < my_cipher_len; i++) {
                if (!isprint(decrypted[i])) {
                    all_printable = 0;
                    break;
                }
            }
            if (!all_printable) {
                continue;
            }

            // (e) Found a printable candidate → tell server
            pthread_mutex_lock(&g_mutex);
            if (!g_password_cracked) {
                // Prepare a small buffer: prefix “CLIENT #k:”, then plaintext bytes
                int prefix_len = snprintf(NULL, 0, "CLIENT #%ld:", idx);
                int total_len = prefix_len + my_cipher_len;
                char *candidate = malloc(total_len + 1);
                snprintf(candidate, prefix_len + 1, "CLIENT #%ld:", idx);
                memcpy(candidate + prefix_len, decrypted, my_cipher_len);
                candidate[total_len] = '\0';

                // Store that pointer in g_plaintext_candidate
                if (g_plaintext_candidate) {
                    free(g_plaintext_candidate);
                }
                g_plaintext_candidate = (unsigned char *)candidate;

                g_password_cracked = 1;
                pthread_cond_broadcast(&g_new_cipher_cond);

                long ts2 = get_unix_timestamp_seconds();
                printf("%ld [DECRYPTER #%ld] [INFO] After decryption(\"",
                       ts2, idx);
                // Print the plaintext in printable/escaped form
                for (size_t i = 0; i < my_cipher_len; i++) {
                    unsigned char c = decrypted[i];
                    if (isprint(c) && c != '\\' && c != '\"') {
                        putchar(c);
                    } else {
                        printf("\\x%02X", c);
                    }
                }
                printf("\"), key guessed (hex): ");
                hex_escape_and_print(trial_key, key_len_bytes, 16);
                printf(", sending to server after %ld iterations\n", iterations);
            }
            pthread_mutex_unlock(&g_mutex);
            break;
        }

        free(trial_key);
        free(decrypted);
        free(my_cipher_copy);

        // 3) Loop—either wait for next ciphertext or exit if needed
    }

    return NULL; // never reached
}