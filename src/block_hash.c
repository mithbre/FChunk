#include <stdio.h>
#include <stdint.h>
#include <gcrypt.h>
#include <getopt.h>

#include "fileops.h"

void usage()
{
        printf("Expected use:\n");
        printf("patch.exe file                  # get initial hashes\n");
        printf("patch.exe (-h hash) file        # compare files\n");
        printf("patch.exe (-m list) file        # create patch\n");
        printf("patch.exe (-p patch) file       # patch file\n\n");
}

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

int main(int argc, char *argv[])
{
        uint32_t BUFFERLEN = 15728640;  //15 MB
        const int HASHLEN = gcry_md_get_algo_dlen( GCRY_MD_SHA1 );
        uint8_t hash[HASHLEN];
        uint8_t *goodHashes = NULL, *curHashes, *badChunks;
        uint32_t readLength, hashInLength, hashOutLength, srcLength, pos;
        uint32_t bitfieldLength, byte, bChunkLength;

        int c;
        while ((c = getopt(argc, argv, "c:hm")) != -1) {
                switch(c) {
                case 'c':
                        BUFFERLEN = atoi(optarg) * 1048576;
                        break;
                case 'h':
                        hashInLength = load_data(&goodHashes, "ghash");
                        if (hashInLength % HASHLEN != 0) {
                                printf("ghash not of correct length.\n");
                                exit(1);
                        }
                        break;
                case 'm':
                        bChunkLength = load_data(&badChunks, "bchunk");
                        printf("%i\n", bChunkLength);

                        exit(1);
                        break;
                default:
                        usage();
                        exit(5);
                }
        }

        // Check to see if the user has a file argument
        // optind should be argc - 1
        if (optind >= argc) {
                usage();
                exit(5);
        }

        // Setup gcrypt
        if (!gcry_check_version (GCRYPT_VERSION)) {
                printf("Failed to load gcrypt.");
                exit(2);
        }
        gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
        gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

        // create a buffer 15 MB in size
        char *buffer = (char*) malloc (sizeof(char) * BUFFERLEN);

        // Ready files
        FILE *srcFile = fopen(argv[optind], "rb");
        check_file(srcFile);
        srcLength = get_file_length(srcFile);
        hashOutLength = (srcLength / BUFFERLEN + 1) * HASHLEN;

        curHashes = (char*) malloc (sizeof(char) * (hashOutLength + 1));

        for (uint32_t chunk = 0; chunk <= srcLength/BUFFERLEN; chunk++) {
                readLength = load_chunk(srcFile, buffer, chunk, BUFFERLEN);
                // Hash the buffer
                gcry_md_hash_buffer(GCRY_MD_SHA1, hash, buffer, readLength);

                #ifdef DEBUG
                print_hash(hash, HASHLEN);
                #endif

                memcpy(&curHashes[HASHLEN * chunk], hash, HASHLEN);
        }
        fclose(srcFile);

        if (goodHashes == NULL) {
                // no comparison, just write out hashes
                writefile("ghash", curHashes, hashOutLength, 0, "wb");
        } else {
                bitfieldLength = ((hashInLength / HASHLEN) + 7) / 8;
                uint8_t *a = calloc(bitfieldLength, sizeof(char));
                for (uint32_t chunk = 0; chunk < hashInLength/HASHLEN; chunk++) {
                        pos = chunk * HASHLEN;
                        if (pos > hashOutLength) {
                                // Missing data in the destination file
                                // fill_with_bad();
                                break;
                        }

                        if (memcmp(&goodHashes[pos], &curHashes[pos],
                            HASHLEN) != 0) {
                                #ifdef DEBUG
                                printf("%2i: Bad\n", chunk);
                                #endif
                                byte = chunk / 8;
                                a[byte] |= 1 << (chunk % 8);
                        }
                }
                writefile("bchunk", a, bitfieldLength, 0, "wb");
        }
        return 0;
}
