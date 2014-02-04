﻿#include <stdio.h>
#include <stdint.h>
#include <gcrypt.h>
#include <getopt.h>

void usage()
{
        printf("Expected use:\n");
        printf("patch.exe file                  # get initial hashes\n");
        printf("patch.exe (-h hash) file        # compare files\n");
        printf("patch.exe (-m list) file        # create patch\n");
        printf("patch.exe (-p patch) file       # patch file\n\n");
}

int load_hashes(uint8_t **loadedHash)
{
        int length;
        FILE *temp = fopen("ghash", "rb");

        // Get length of file
        fseek(temp, 0, SEEK_END);
        length = ftell(temp);
        rewind(temp);

        // Allocate space for all Hashes and copy them in
        *loadedHash = (uint8_t *) malloc(sizeof(uint8_t) * (length + 1));
        fread(*loadedHash, sizeof(uint8_t), length, temp);
        fclose(temp);
        return length;
}

void check_file(FILE *f)
{
        if (f == NULL) {
                printf("Failed to open file.");
                exit(3);
        }
}

int main(int argc, char *argv[])
{
        int BUFFERLEN = 15728640;
        const int HASHLEN = gcry_md_get_algo_dlen( GCRY_MD_SHA1 );
        unsigned char hash[HASHLEN];
        uint8_t *goodHashes;
        uint32_t readLength, hashInLength;

        int c;
        while ((c = getopt(argc, argv, "c:h")) != -1) {
                switch(c) {
                        case 'c':
                                BUFFERLEN = atoi(optarg) * 1048576;
                                break;
                        case 'h':
                                hashInLength = load_hashes(&goodHashes);
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
        FILE *f = fopen(argv[optind], "rb");
        check_file(f);
        FILE *hashOut = fopen("ghash", "wb");
        check_file(hashOut);

        do {
                // Read into buffer
                readLength = fread(buffer, sizeof(char), BUFFERLEN, f);
                if (readLength == 0) {
                        // nothing more to do, skip.
                        continue;
                }

                // Hash the buffer
                gcry_md_hash_buffer(GCRY_MD_SHA1, hash, buffer, readLength);

                #ifdef DEBUG
                // Allocate space for the human readable sha1 hash
                char *fHash = (char *) malloc(sizeof(char) * (HASHLEN * 2 + 1));
                char *p = fHash;

                for(int i = 0; i < HASHLEN; i++, p += 2) {
                        snprintf( p, 3, "%02x", hash[i] );
                }
                printf("%s\n", fHash);
                #endif

                fwrite(hash, sizeof(char), sizeof(hash), hashOut);
        } while (readLength == BUFFERLEN);
        fclose(f);
        fclose(hashOut);
        return 0;
}
