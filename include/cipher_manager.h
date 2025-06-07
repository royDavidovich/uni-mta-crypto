#ifndef MTA_CRYPTO_H
#define MTA_CRYPTO_H

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <stddef.h>     // for size_t
#include <pthread.h>    // for pthread types

#ifdef __cplusplus
extern "C" {
#endif

    /* ────────────────────────────────────────────────────────────────────────── */
    /* Shared global state */
    /* ────────────────────────────────────────────────────────────────────────── */
    typedef struct {
        char *guess;   // the decrypted password
        long id;       // the thread ID that guessed it
    } CrackResult;

    extern pthread_mutex_t g_mutex;
    extern pthread_cond_t  g_new_cipher_cond;

    extern int g_password_cracked;
    extern char *g_ciphertext;
    extern size_t g_ciphertext_len;
    extern CrackResult *g_plaintext_candidate;

    extern int g_timeout_secs;
    extern int g_password_len;



    /* ────────────────────────────────────────────────────────────────────────── */
    /* Utility function declarations */
    /* ────────────────────────────────────────────────────────────────────────── */

    /**
     * Return the current Unix timestamp (in seconds).
     */
    long get_unix_timestamp_seconds(void);

    /**
     * Print `data` as hex-escaped (e.g., \x41\x42...) with optional truncation.
     * If `max_len` is 0 or negative, print full length.
     */
    void hex_escape_and_print(const char *data, size_t len, int max_len);

    void print_escaped(const char *buf, size_t len);


#ifdef __cplusplus
}
#endif

#endif // MTA_CRYPTO_H
