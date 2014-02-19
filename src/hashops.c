#include <stdio.h>
#include <stdint.h>
#include <gcrypt.h>

#include "fileops.h"

void print_hash(uint8_t *hash, const uint32_t HASHLEN)
{
        // Allocate space for the human readable sha1 hash
        char *fHash = (char *) malloc(sizeof(char) * (HASHLEN * 2 + 1));
        char *p = fHash;

        for(int i = 0; i < HASHLEN; i++, p += 2) {
                snprintf( p, 3, "%02x", hash[i] );
        }
        printf("%s\n", fHash);
        free(fHash);
}

void hash_file(FILE *srcFile, uint32_t srcLength, uint8_t *curHashes,
    const int HASHLEN, uint32_t BUFFERLEN)
{
        uint8_t hash[HASHLEN];
        uint32_t readLength;
        // Setup gcrypt
        if (!gcry_check_version (GCRYPT_VERSION)) {
                printf("Failed to load gcrypt.");
                exit(2);
        }
        gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
        gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

        // create a buffer 15 MB in size
        char *buffer = (char*) malloc (sizeof(char) * BUFFERLEN);

        for (uint32_t chunk = 0; chunk <= srcLength/BUFFERLEN; chunk++) {
                readLength = load_chunk(srcFile, buffer, chunk, BUFFERLEN);
                // Hash the buffer
                gcry_md_hash_buffer(GCRY_MD_SHA1, hash, buffer, readLength);

                #ifdef DEBUG
                print_hash(hash, HASHLEN);
                #endif

                memcpy(&curHashes[HASHLEN * chunk], hash, HASHLEN);
        }
        free(buffer);
}

void cmp_hashes(uint8_t *curHashes, uint8_t *goodHashes, uint32_t hashOutLength, uint8_t *a,
    const int HASHLEN, uint32_t hashInLength)
{
        uint8_t byte;
        uint32_t pos;

        for (uint32_t chunk = 0; chunk < hashInLength/HASHLEN; chunk++) {
                pos = chunk * HASHLEN;
                if (pos > hashOutLength) {
                        // Missing data in the destination file
                        // fill_with_bad();
                        break;
                }

                if (memcmp(&goodHashes[pos], &curHashes[pos], HASHLEN) != 0) {
                        #ifdef DEBUG
                        printf("%2i: Bad\n", chunk);
                        #endif
                        byte = chunk / 8;
                        a[byte] |= 1 << (chunk % 8);
                }
        }
}
