#include <mta_crypt.h>
#include <mta_rand.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "decryptor.h"
#include "cipher_manager.h"

static void wait_for_ciphertext(char **copy, size_t *len)
{
    pthread_mutex_lock(&g_mutex);
    while (g_ciphertext == NULL)
    {
        pthread_cond_wait(&g_new_cipher_cond, &g_mutex);
    }

    *len = g_ciphertext_len;
    *copy = malloc(*len);
    if (!*copy)
    {
        fprintf(stderr, "malloc(my_cipher_copy) failed\n");
        exit(EXIT_FAILURE);
    }

    memcpy(*copy, g_ciphertext, *len);
    pthread_mutex_unlock(&g_mutex);
}

static int is_all_printable(const char *text, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        if (!isprint(text[i]))
        {
            return 0;
        }
    }
    return 1;
}

static void submit_plaintext_candidate(long idx, const char *decrypted, const char *key,
                                       size_t cipher_len, size_t key_len_bytes, long iterations)
{
    pthread_mutex_lock(&g_mutex);
    if (!g_password_cracked)
    {
        char *candidate = malloc(cipher_len + 1);

        memcpy(candidate, decrypted, cipher_len);
        candidate[cipher_len] = '\0';

        if (g_plaintext_candidate == NULL)
        {
            g_plaintext_candidate = malloc(sizeof(CrackResult));
        }

        g_plaintext_candidate->guess = candidate;
        g_plaintext_candidate->id = idx;

        pthread_cond_broadcast(&g_new_cipher_cond);
    }
    else
    {
        long ts = get_unix_timestamp_seconds();
        printf("%ld [DECRYPTER #%ld] [INFO] After decryption(\"", ts, idx);
        print_escaped(decrypted, cipher_len);
        printf("\"), key guessed (hex): ");
        hex_escape_and_print(key, key_len_bytes, 16);
        printf(", sending to server after %ld iterations\n", iterations);
    }
    
    pthread_mutex_unlock(&g_mutex);
}

static void brute_force_decryption(long idx, char *ciphertext, size_t cipher_len)
{
    size_t key_len = cipher_len / 8;
    char *trial_key = malloc(key_len);
    char *decrypted = malloc(cipher_len);
    if (!trial_key || !decrypted)
    {
        fprintf(stderr, "malloc(trial_key/decrypted) failed\n");
        exit(EXIT_FAILURE);
    }

    long iterations = 0;
    long start_ts = get_unix_timestamp_seconds();

    while (1)
    {
        iterations++;
        pthread_mutex_lock(&g_mutex);
        if (g_password_cracked || strcmp(g_ciphertext, ciphertext) != 0)
        {
            // cipher changed
            pthread_mutex_unlock(&g_mutex);
            break;
        }
        pthread_mutex_unlock(&g_mutex);

        MTA_get_rand_data(trial_key, key_len);

        unsigned int out_len = (unsigned int)cipher_len;
        if (MTA_decrypt(trial_key, (unsigned int)key_len, ciphertext,
                        (unsigned int)cipher_len, decrypted, &out_len) != MTA_CRYPT_RET_OK)
        {
            continue;
        }

        if (!is_all_printable(decrypted, cipher_len))
        {
            continue;
        }

        submit_plaintext_candidate(idx, decrypted, trial_key, cipher_len, key_len, iterations);

        break;
    }

    free(trial_key);
    free(decrypted);
}

void *decrypter_thread_fn(void *arg)
{
    long idx = (long)arg;

    while (1)
    {

        // TODO maybe remove local copy, can create sync issues

        char *my_cipher_copy = NULL;
        size_t my_cipher_len = 0;

        wait_for_ciphertext(&my_cipher_copy, &my_cipher_len);

        // TODO check runs with wrong password (add breakpoint in encryptor if statement that check it)
        brute_force_decryption(idx, my_cipher_copy, my_cipher_len);
        free(my_cipher_copy);
    }

    return NULL;
}
