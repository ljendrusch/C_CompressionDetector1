#ifndef UTILS
#define UTILS

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

char* slurp_file(const char* filename);
void read_json(char** json_raw, char**** json, uint16_t* n_fields);
void check_port(const char* filename, char* port_k, uint16_t port_v);
void free_json(char*** json, uint16_t n_fields, char* json_raw);

#endif
