#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void check_file(FILE *f)
{
        if (f == NULL) {
                printf("Failed to open file.");
                exit(3);
        }
}

uint32_t get_file_length(FILE *temp)
{
        fseek(temp, 0, SEEK_END);
        uint32_t length = ftell(temp);
        rewind(temp);
        return length;
}

uint32_t load_chunk(FILE *f, char *buffer, uint32_t chunk, uint32_t chunk_size)
{
        // Read into buffer
        fseek(f, chunk * chunk_size, SEEK_SET);
        uint32_t readLength = fread(buffer, sizeof(char), chunk_size, f);
        return readLength;
}

int writefile(char *name, uint8_t *write, uint32_t length, uint32_t pos,
    char *opentype)
{
        FILE *f = fopen(name, opentype);
        check_file(f);
        fseek(f, pos, SEEK_SET);
        fwrite(write, sizeof(char), length, f);
        fclose(f);
}

uint32_t load_data(uint8_t **loadMe, char *name)
{
        uint32_t length;
        FILE *temp = fopen(name, "rb");

        length = get_file_length(temp);

        *loadMe = (uint8_t *) malloc(sizeof(uint8_t) * (length + 1));
        fread(*loadMe, sizeof(uint8_t), length, temp);
        fclose(temp);
        return length;
}
