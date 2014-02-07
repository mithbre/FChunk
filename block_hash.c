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

uint32_t get_file_length(FILE *temp)
{
        fseek(temp, 0, SEEK_END);
        uint32_t length = ftell(temp);
        rewind(temp);
        return length;
}

uint32_t load_hashes(uint8_t **loadedHash)
{
        uint32_t length;
        FILE *temp = fopen("ghash", "rb");

        length = get_file_length(temp);

        // Allocate space for all Hashes and copy them in
        *loadedHash = (uint8_t *) malloc(sizeof(uint8_t) * (length + 1));
        fread(*loadedHash, sizeof(uint8_t), length, temp);
        fclose(temp);
        return length;
}

uint32_t load_chunk(FILE *f, char *buffer, uint32_t chunk, uint32_t chunk_size)
{
        // Read into buffer
        fseek(f, chunk * chunk_size, SEEK_SET);
        uint32_t readLength = fread(buffer, sizeof(char), chunk_size, f);
        return readLength;
}

void check_file(FILE *f)
{
        if (f == NULL) {
                printf("Failed to open file.");
                exit(3);
        }
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
        uint8_t *goodHashes, *curHashes;
        uint32_t readLength, hashInLength, hashOutLength, srcLength;

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
        FILE *srcFile = fopen(argv[optind], "rb");
        check_file(srcFile);
        srcLength = get_file_length(srcFile);
        hashOutLength = (srcLength / BUFFERLEN + 1) * HASHLEN;

        curHashes = (char*) malloc (sizeof(char) * (hashOutLength + 1));
        curHashes[0] = '\0';

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

        FILE *hashOut = fopen("ghash", "wb");
        check_file(hashOut);
        fwrite(curHashes, sizeof(char), hashOutLength, hashOut);
        fclose(hashOut);
        return 0;
}
