#ifndef MTA_CRYPTO_H
#define MTA_CRYPTO_H

#define _GNU_SOURCE

#include <stddef.h>  // for size_t
#include <pthread.h> // for pthread types

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct
    {
        char *guess; // the decrypted password
        long id;     // the thread ID that guessed it
    } CrackResult;

    extern pthread_mutex_t g_mutex;
    extern pthread_cond_t g_new_cipher_cond;

    extern int g_password_cracked_or_timeout;
    extern char *g_ciphertext;
    extern size_t g_ciphertext_len;
    extern CrackResult *g_plaintext_candidate;

    extern int g_timeout_secs;
    extern int g_password_len;

    /**
     * Return the current Unix timestamp (in seconds).
     */
    long get_unix_timestamp_seconds(void);

    /**
     * Print `data` as hex-escaped
     * If `max_len` is 0 or negative, print full length.
     */
    void hex_escape_and_print(const char *data, int len, int max_len);

    void print_escaped(const char *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif // MTA_CRYPTO_H