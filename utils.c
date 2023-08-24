
#include "utils.h"


char* slurp_file(const char* filename)
{
    FILE* f = fopen(filename, "rb");
    if (!f)
    {
        printf("Error opening file %s\n", filename);
        exit(1);
    }

    fseek(f, 0, SEEK_END);
    long f_len = ftell(f);
    if (f_len < 9)
    {
        printf("Json file empty\n");
        exit(1);
    }
    fseek(f, 0, SEEK_SET);

    char* data = malloc(f_len+1);

    fread(data, 1, f_len, f);
    data[f_len] = '\0';
    fclose(f);

    return data;
}

void read_json(char** json_raw, char**** json, uint16_t* n_fields)
{
    *n_fields = 0;

    char c;
    uint32_t i = 1;
    while ((c = (*json_raw)[i]) != '\0')
    {
        if ((*json_raw)[i] == '\n' && (*json_raw)[i-1] != '{' && (*json_raw)[i-1] != '}' && (*json_raw)[i-1] != '\n')
            (*n_fields)++;
        i++;
    }

    (*json) = malloc((*n_fields) * sizeof(char**));

    i = 0;
    uint32_t left = 0, json_idx = 0;
    uint8_t kv = 0;
    while ((c = (*json_raw)[i]) != '\0')
    {
        if (c == '"')
        {
            if (left == 0)
                left = i+1;
            else
            {
                if (!kv) (*json)[json_idx] = malloc(2 * sizeof(char*));
                (*json)[json_idx][kv] = malloc(1 + i - left);
                for (uint16_t j = left; j < i; j++)
                    (*json)[json_idx][kv][j-left] = (*json_raw)[j];

                (*json)[json_idx][kv][i - left] = '\0';
                left = 0;
                if (kv) json_idx++;
                kv = (kv+1)%2;
            }
        }
        i++;
    }
}

void check_port(const char* filename, char* port_k, uint16_t port_v)
{
	if (port_v <= 0 || port_v > 65535)
	{
		printf("%s invalid %s value %d\n", filename, port_k, port_v);
		exit(1);
	}
}

void free_json(char*** json, uint16_t n_fields, char* json_raw)
{
    for (uint16_t i = 0; i < n_fields; i++)
    {
        free(json[i][0]);
        free(json[i][1]);
        free(json[i]);
    }
    free(json);
    if (json_raw) free(json_raw);
}
