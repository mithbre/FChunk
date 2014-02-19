#include <stdio.h>
#include <stdint.h>
#include <gcrypt.h>
#include <getopt.h>

#include "fileops.h"
#include "hashops.h"

#define HASH  1
#define CHECK 2
#define MAKE  4
#define PATCH 8

void usage()
{
        printf("Expected use:\n");
        printf("patch.exe file                  # get initial hashes\n");
        printf("patch.exe (-h hash) file        # compare files\n");
        printf("patch.exe (-m list) file        # create patch\n");
        printf("patch.exe (-p patch) file       # patch file\n\n");
}

int main(int argc, char *argv[])
{
        uint32_t BUFFERLEN = 15728640;  //15 MB
        const int HASHLEN = gcry_md_get_algo_dlen( GCRY_MD_SHA1 );
        uint8_t *curHashes, *badChunks, *goodHashes, mode = HASH;
        uint32_t hashOutLength, srcLength;
        uint32_t bitfieldLength, bChunkLength, hashInLength;

        int c;
        while ((c = getopt(argc, argv, "c:hm")) != -1) {
                switch(c) {
                case 'c':
                        BUFFERLEN = atoi(optarg) * 1048576;
                        break;
                case 'h':
                        mode = CHECK;
                        // Load hash file
                        hashInLength = load_data(&goodHashes, "ghash");
                        if (hashInLength % HASHLEN != 0) {
                                printf("ghash not of correct length.\n");
                                exit(1);
                        }
                        break;
                case 'm':
                        mode = MAKE;
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

        // Ready files
        FILE *srcFile = fopen(argv[optind], "rb");
        check_file(srcFile);
        srcLength = get_file_length(srcFile);
        hashOutLength = (srcLength / BUFFERLEN + 1) * HASHLEN;
        curHashes = (uint8_t*) malloc (sizeof(uint8_t) * (hashOutLength + 1));

        if (mode & HASH) {
                hash_file(srcFile, srcLength, curHashes, HASHLEN, BUFFERLEN);
                fclose(srcFile);
                writefile("ghash", curHashes, hashOutLength, 0, "wb");
        } else if (mode & CHECK) {
                /* if new file is longer...ignore, warn? */
                hash_file(srcFile, srcLength, curHashes, HASHLEN, BUFFERLEN);
                fclose(srcFile);

                // Allocate space for all chunk statuses
                bitfieldLength = ((hashInLength / HASHLEN) + 7) / 8;
                uint8_t *a = calloc(bitfieldLength, sizeof(char));

                cmp_hashes(curHashes, goodHashes, hashOutLength, a, HASHLEN,
                    hashInLength);
                writefile("bchunk", a, bitfieldLength, 0, "wb");
                free(a);
        }
        return 0;
}
