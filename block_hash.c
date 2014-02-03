#include <stdio.h>
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

int main(int argc, char *argv[])
{
        int BUFFERLEN = 15728640;
        const int hashLength = gcry_md_get_algo_dlen( GCRY_MD_SHA1 );
        unsigned char hash[hashLength];
        uint32_t readLength;
        char *fileName;

        int c;
        while ((c = getopt(argc, argv, "c:")) != -1) {
                switch(c) {
                        case 'c':
                                BUFFERLEN = atoi(optarg) * 1048576;
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
        if (f == NULL) {
                printf("Failed to open file.");
                exit(3);
        }

        FILE *hashOut = fopen("ghash", "wb");

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
                char *fHash = (char *) malloc(sizeof(char) * (hashLength * 2 + 1));
                char *p = fHash;

                for(int i = 0; i < hashLength; i++, p += 2) {
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
