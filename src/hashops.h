void print_hash(uint8_t *hash, const uint32_t HASHLEN);

void hash_file(FILE *srcFile, uint32_t srcLength, uint8_t *curHashes,
    const int HASHLEN, uint32_t BUFFERLEN);

void cmp_hashes(uint8_t *curHashes, uint8_t *goodHashes, uint32_t hashOutLength, uint8_t *a,
    const int HASHLEN, uint32_t hashInLength);