/*
 * src/mta_crypto.c
 *
 * A minimal skeleton for Exercise 2 (MTA Crypto).
 *
 * One "Encrypter" thread produces a random password & key, encrypts it via MTA_encrypt(),
 * and then signals "new ciphertext available" to all decrypter threads.  Decrypters race
 * to guess the key by random trial; if they find a printable plaintext, they send it back
 * to the encrypter for verification.
 *
 * Flags supported:
 *   -n | --num-of-decrypters   <number_of_decrypter_threads>
 *   -l | --password-length     <password_length>   (must be multiple of 8)
 *   -t | --timeout             <timeout_in_seconds>   (optional)
 *
 * On timeout or on correct guess, encrypter generates a fresh password & key.
 */

// ─────────────────────────────────────────────────────────────────────────────
// File: src/mta_crypto.c  (patched)
// ─────────────────────────────────────────────────────────────────────────────

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

#include <openssl/err.h>
#include <openssl/rand.h>

#include "mta_rand.h"
#include "mta_crypt.h"

/* ────────────────────────────────────────────────────────────────────────── */
/* Because mta_rand.h only gives us MTA_get_rand_char(), we must write our   */
/* own mta_generate_printable(...) here.                                       */
/* (This was why the compiler warned “implicit declaration of function       */
/*  ‘mta_generate_printable’.”                                              */
/*                                                                           */
/* We will spin until MTA_get_rand_char() yields an isprint() character.     */
/* ────────────────────────────────────────────────────────────────────────── */
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


/* ────────────────────────────────────────────────────────────────────────── */
/* Global shared state, synchronization, etc.  (unchanged from skeleton)      */
/* ────────────────────────────────────────────────────────────────────────── */
static unsigned char *g_ciphertext = NULL;
static size_t         g_ciphertext_len = 0;
static unsigned char *g_plaintext_candidate = NULL;
static volatile int   g_password_cracked = 0;

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_new_cipher_cond = PTHREAD_COND_INITIALIZER;

static int g_num_decrypters = 1;
static int g_password_len   = 8;  // must be multiple of 8
static int g_timeout_secs   = 0;  // 0 = no timeout

/* Helper: wait for either “someone cracked it” or a timeout (if set). */
static void wait_for_crack_or_timeout(struct timespec *deadline)
{
    if (g_timeout_secs > 0) {
        pthread_cond_timedwait(&g_new_cipher_cond, &g_mutex, deadline);
    } else {
        while (!g_password_cracked) {
            pthread_cond_wait(&g_new_cipher_cond, &g_mutex);
        }
    }
}

/* ───────────────────────────────────────────────────────────────────────────── */
/* Helper to get current Unix‐epoch timestamp (in seconds). */
static long get_unix_timestamp_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec;
}

/* ───────────────────────────────────────────────────────────────────────────── */
/* When we want to log raw bytes (e.g., a key or ciphertext), we’ll print them */
/* as an escaped hexstring, but truncated if too long.                          */
static void hex_escape_and_print(const unsigned char *data, size_t len, size_t max_output_bytes) {
    // Print up to max_output_bytes in hex, then “…” if more.
    size_t to_show = (len < max_output_bytes ? len : max_output_bytes);
    for (size_t i = 0; i < to_show; i++) {
        printf("%02X", data[i]);
    }
    if (len > max_output_bytes) {
        printf("…");
    }
}

/* ────────────────────────────────────────────────────────────────────────── */
/* Encrypter thread: generate printable password, generate random key, encrypt */
/* via MTA_encrypt(), then broadcast to all decrypters.                       */
/* ────────────────────────────────────────────────────────────────────────── */
static void *encrypter_thread_fn(void *arg)
{
    (void)arg;
    unsigned char *plaintext = NULL;
    unsigned char *key       = NULL;

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
        key = malloc(key_len_bytes);
        if (!key) {
            fprintf(stderr, "malloc(key) failed\n");
            exit(EXIT_FAILURE);
        }
        if (RAND_bytes(key, key_len_bytes) != 1) {
            fprintf(stderr, "RAND_bytes() failed\n");
            exit(EXIT_FAILURE);
        }

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
/* ────────────────────────────────────────────────────────────────────────── */
/* Decrypter thread: wait for g_ciphertext, then brute‐force keys until      */
/* we see “all bytes are printable.”  Once found, set g_password_cracked = 1.  */
/* ────────────────────────────────────────────────────────────────────────── */
static void *decrypter_thread_fn(void *arg)
{
    long idx = (long)arg; // client‐ID (0,1,2,…)
    unsigned char *my_cipher_copy = NULL;
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
        unsigned char *trial_key = malloc(key_len_bytes);
        unsigned char *decrypted = malloc(my_cipher_len);
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
            if (RAND_bytes(trial_key, key_len_bytes) != 1) {
                fprintf(stderr, "[DECRYPTER #%ld] RAND_bytes() failed\n", idx);
                exit(EXIT_FAILURE);
            }

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
/* ────────────────────────────────────────────────────────────────────────── */
/* main(): parse -n, -l, -t, spawn threads, join (skeleton from before)     */
/* ────────────────────────────────────────────────────────────────────────── */
static void print_usage_and_exit(const char *progname)
{
    fprintf(stderr,
        "Usage: %s -n <num-of-decrypters> -l <password-length> [-t <timeout-seconds>]\n"
        "       -n | --num-of-decrypters   (required) Number of decrypter threads (integer ≥ 1)\n"
        "       -l | --password-length     (required) Password length (must be multiple of 8)\n"
        "       -t | --timeout             (optional) Timeout in seconds (≥ 0; default: none)\n",
        progname
    );
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    int opt;
    int saw_n = 0, saw_l = 0;   // flags to track whether -n and -l were provided
    long temp;

    /* Instead of defaulting to 1 or 8, initialize to 0 so we can detect “not provided.” */
    int g_num_decrypters = 0;
    int g_password_len   = 0;
    int g_timeout_secs   = 0;  /* default = no timeout */

    static struct option long_opts[] = {
        {"num-of-decrypters", required_argument, 0, 'n'},
        {"password-length",   required_argument, 0, 'l'},
        {"timeout",           required_argument, 0, 't'},
        {0, 0, 0, 0}
    };

    /* ------------------------------------------------------------
     * 1) Parse command-line flags.
     * ------------------------------------------------------------ */
    while ((opt = getopt_long(argc, argv, "n:l:t:", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'n':
                saw_n = 1;
                temp = strtol(optarg, NULL, 10);
                if (temp < 1 || temp > INT_MAX) {
                    fprintf(stderr, "Error: -n must be an integer ≥ 1.\n");
                    print_usage_and_exit(argv[0]);
                }
                g_num_decrypters = (int)temp;
                break;

            case 'l':
                saw_l = 1;
                temp = strtol(optarg, NULL, 10);
                if (temp < 8 || (temp % 8) != 0 || temp > INT_MAX) {
                    fprintf(stderr, "Error: -l must be a multiple of 8 (≥ 8).\n");
                    print_usage_and_exit(argv[0]);
                }
                g_password_len = (int)temp;
                break;

            case 't':
                temp = strtol(optarg, NULL, 10);
                if (temp < 0 || temp > INT_MAX) {
                    fprintf(stderr, "Error: -t must be a non-negative integer.\n");
                    print_usage_and_exit(argv[0]);
                }
                g_timeout_secs = (int)temp;
                break;

            default:
                /* getopt_long already prints a brief “invalid option” message */
                print_usage_and_exit(argv[0]);
        }
    }

    /* ------------------------------------------------------------
     * 2) Ensure both -n and -l were provided exactly once.
     * ------------------------------------------------------------ */
    if (!saw_n || !saw_l) {
        fprintf(stderr, "Error: both -n and -l are required.\n");
        print_usage_and_exit(argv[0]);
    }

    /* ------------------------------------------------------------
     * 3) Make sure there are no extra arguments on the command line
     *    (i.e. “./mta_crypto -n 2 -l 16 foo” is invalid).
     * ------------------------------------------------------------ */
    if (optind < argc) {
        fprintf(stderr, "Error: unexpected argument: %s\n", argv[optind]);
        print_usage_and_exit(argv[0]);
    }

    /* ------------------------------------------------------------
     * 4) If we reach here, -n and -l are valid.  We can safely
     *    proceed to spawn threads (not shown in this snippet).
     * ------------------------------------------------------------ */
    printf("Configuration:\n");
    printf("  Number of decrypter threads: %d\n", g_num_decrypters);
    printf("  Password length (bytes)   : %d\n", g_password_len);
    printf("  Timeout (seconds)         : %d\n", g_timeout_secs);

    /* Spawn the encrypter thread */
    pthread_t encrypter_thread;
    if (pthread_create(&encrypter_thread, NULL, encrypter_thread_fn, NULL) != 0) {
        perror("pthread_create(encrypter)");
        exit(EXIT_FAILURE);
    }

    /* Spawn each decrypter thread */
    pthread_t *decrypters = malloc(sizeof(pthread_t) * g_num_decrypters);
    if (!decrypters) {
        fprintf(stderr, "Error: malloc(decrypters array)\n");
        exit(EXIT_FAILURE);
    }
    for (long i = 0; i < g_num_decrypters; i++) {
        if (pthread_create(&decrypters[i], NULL, decrypter_thread_fn, (void *)i) != 0) {
            fprintf(stderr, "Error: pthread_create(decrypter %ld)\n", i);
            exit(EXIT_FAILURE);
        }
    }

    /* Join threads (in this skeleton, they loop forever) */
    pthread_join(encrypter_thread, NULL);
    for (int i = 0; i < g_num_decrypters; i++) {
        pthread_join(decrypters[i], NULL);
    }
    free(decrypters);

    return 0;
}