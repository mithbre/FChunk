#include <stdio.h>
#include <stdint.h>
#include <gcrypt.h>

#define BUFFERLEN 15728640
int main()
{
        const int hashLength = gcry_md_get_algo_dlen( GCRY_MD_SHA1 );
        unsigned char hash[hashLength];
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

        // Load file
        //FILE *f = fopen("test_1m", "rb");       //CAA76193D76C6F3008392E249DFB1C5019857154
        FILE *f = fopen("test_15m", "rb");      //2FEDA21AE54F64897F70F1A0947E33F4CA3CE8B9
        if (f == NULL) {
                printf("Failed to open file.");
                exit(3);
        }

        do {
                // Read into buffer
                readLength = fread(buffer, sizeof(char), BUFFERLEN, f);
                if (readLength == 0) {
                        // nothing more to do, skip.
                        continue;
                }

                // Hash the buffer
                gcry_md_hash_buffer(GCRY_MD_SHA1, hash, buffer, readLength);

                // Allocate space for the human readable sha1 hash
                char *fHash = (char *) malloc(sizeof(char) * (hashLength * 2 + 1));
                char *p = fHash;

                for(int i = 0; i < hashLength; i++, p += 2) {
                        snprintf( p, 3, "%02x", hash[i] );
                }
                printf("%s\n", fHash);
        } while (readLength == BUFFERLEN);
        fclose(f);
        return 0;
}
