#ifndef PASSWALL_CHACHA_RUNTIME_CONFIG_H
#define PASSWALL_CHACHA_RUNTIME_CONFIG_H

#include <string.h>

#define PASSWALL_CHACHA_WORKERS_AUTO (-1)
#define PASSWALL_CHACHA_DEFAULT_THRESHOLD_KIB 4U

static inline int
passwall_chacha_parse_workers(const char *text, int *workers)
{
    if(!text || !workers)
        return -1;
    if(strcmp(text, "auto") == 0) {
        *workers = PASSWALL_CHACHA_WORKERS_AUTO;
        return 0;
    }
    if(text[1] != '\0' || text[0] < '0' || text[0] > '3')
        return -1;
    *workers = text[0] - '0';
    return 0;
}

static inline int
passwall_chacha_parse_threshold_kib(const char *text, unsigned int *kib)
{
    if(!text || !kib)
        return -1;
    if(strcmp(text, "4") == 0) *kib = 4U;
    else if(strcmp(text, "8") == 0) *kib = 8U;
    else if(strcmp(text, "16") == 0) *kib = 16U;
    else if(strcmp(text, "24") == 0) *kib = 24U;
    else if(strcmp(text, "32") == 0) *kib = 32U;
    else return -1;
    return 0;
}

static inline int
passwall_chacha_threshold_valid_bytes(unsigned int bytes)
{
    return bytes == 4096U || bytes == 8192U || bytes == 16384U ||
           bytes == 24576U || bytes == 32768U;
}

#endif
