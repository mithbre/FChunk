void check_file(FILE *f);


uint32_t get_file_length(FILE *temp);


uint32_t load_chunk(FILE *f, char *buffer, uint32_t chunk, uint32_t chunk_size);


int writefile(char *name, uint8_t *write, uint32_t length, uint32_t pos,
    char *opentype);


uint32_t load_data(uint8_t **loadMe, char *name);
