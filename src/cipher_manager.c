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
#include <ctype.h>       // for isprint()
#include <limits.h>
//

#include <mta_rand.h>
#include <mta_crypt.h>

#include "cipher_manager.h"
#include "decryptor.h"
#include "encryptor.h"

/* ────────────────────────────────────────────────────────────────────────── */
/* Global shared state, synchronization, etc.  (unchanged from skeleton)      */
/* ────────────────────────────────────────────────────────────────────────── */
char *g_ciphertext = NULL;
size_t         g_ciphertext_len = 0;
CrackResult *g_plaintext_candidate = NULL;
int   g_password_cracked = 0;

pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  g_new_cipher_cond = PTHREAD_COND_INITIALIZER;

int g_num_decrypters = 0;
int g_password_len   = 0;  // must be multiple of 8
int g_timeout_secs   = 0;  // 0 = no timeout


/* ────────────────────────────────────────────────────────────────────────── */
/* Because mta_rand.h only gives us MTA_get_rand_char(), we must write our   */
/* own mta_generate_printable(...) here.                                       */
/* (This was why the compiler warned “implicit declaration of function       */
/*  ‘mta_generate_printable’.”                                              */
/*                                                                           */
/* We will spin until MTA_get_rand_char() yields an isprint() character.     */
/* ────────────────────────────────────────────────────────────────────────── */

/* Helper: wait for either “someone cracked it” or a timeout (if set). */
void wait_for_crack_or_timeout(struct timespec *deadline)
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
long get_unix_timestamp_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec;
}

// Helper: print password or candidate with escapes for non-printable chars
void print_escaped(const char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        char c = buf[i];
        if (isprint(c) && c != '\\' && c != '\"') {
            putchar(c);
        } else {
            printf("\\x%02X", c);
        }
    }
}


/* ───────────────────────────────────────────────────────────────────────────── */
/* When we want to log raw bytes (e.g., a key or ciphertext), we’ll print them */
/* as an escaped hexstring, but truncated if too long.                          */

void hex_escape_and_print(const char *data, size_t len, int max_output_bytes) {
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

/* Parse command line arguments, set globals. Exits on error. */
void parse_command_line(int argc, char **argv)
{
    int opt;
    int saw_n = 0, saw_l = 0;
    long temp;

    static struct option long_opts[] = {
        {"num-of-decrypters", required_argument, 0, 'n'},
        {"password-length",   required_argument, 0, 'l'},
        {"timeout",           required_argument, 0, 't'},
        {0, 0, 0, 0}
    };

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
                print_usage_and_exit(argv[0]);
        }
    }

    if (!saw_n || !saw_l) {
        fprintf(stderr, "Error: both -n and -l are required.\n");
        print_usage_and_exit(argv[0]);
    }

    if (optind < argc) {
        fprintf(stderr, "Error: unexpected argument: %s\n", argv[optind]);
        print_usage_and_exit(argv[0]);
    }
}

/* Print current configuration */
void print_configuration(void)
{
    printf("Configuration:\n");
    printf("  Number of decrypter threads: %d\n", g_num_decrypters);
    printf("  Password length (bytes)     : %d\n", g_password_len);
    printf("  Timeout (seconds)           : %d\n", g_timeout_secs);
}

/* Create encrypter thread, exit on failure */
pthread_t create_encrypter_thread(void)
{
    pthread_t thread;
    if (pthread_create(&thread, NULL, encrypter_thread_fn, NULL) != 0) {
        perror("pthread_create(encrypter)");
        exit(EXIT_FAILURE);
    }
    return thread;
}

/* Create decrypter threads, exit on failure */
pthread_t *create_decrypter_threads(int num)
{
    pthread_t *threads = malloc(sizeof(pthread_t) * num);
    if (!threads) {
        fprintf(stderr, "Error: malloc(decrypters array)\n");
        exit(EXIT_FAILURE);
    }
    for (long i = 0; i < num; i++) {
        if (pthread_create(&threads[i], NULL, decrypter_thread_fn, (void *)i) != 0) {
            fprintf(stderr, "Error: pthread_create(decrypter %ld)\n", i);
            exit(EXIT_FAILURE);
        }
    }
    return threads;
}

/* Join all threads */
void join_threads(pthread_t encrypter_thread, pthread_t *decrypters, int num)
{
    pthread_join(encrypter_thread, NULL);
    for (int i = 0; i < num; i++) {
        pthread_join(decrypters[i], NULL);
    }
    free(decrypters);
}

int main(int argc, char **argv)
{
    parse_command_line(argc, argv);

    print_configuration();

    MTA_crypt_init();

    pthread_t encrypter_thread = create_encrypter_thread();
    pthread_t *decrypters = create_decrypter_threads(g_num_decrypters);

    join_threads(encrypter_thread, decrypters, g_num_decrypters);

    return 0;
}
