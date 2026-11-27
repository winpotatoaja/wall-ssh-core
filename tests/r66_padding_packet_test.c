#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

static int ssh_padding_valid(size_t padding, size_t packet_length)
{
    return padding >= 4U && padding <= packet_length - 1U;
}

int main(void)
{
    const size_t packet_length = 32U;
    size_t padding;

    for(padding = 0U; padding <= 3U; padding++) {
        if(ssh_padding_valid(padding, packet_length)) {
            fprintf(stderr, "FAIL: padding=%zu was accepted\n", padding);
            return 1;
        }
    }
    if(!ssh_padding_valid(4U, packet_length)) {
        fprintf(stderr, "FAIL: padding=4 was rejected\n");
        return 1;
    }
    if(ssh_padding_valid(packet_length - 1U, packet_length) == 0)
        return 1;
    if(ssh_padding_valid(packet_length, packet_length)) {
        fprintf(stderr, "FAIL: upper padding bound was accepted\n");
        return 1;
    }

    puts("PASS: malformed SSH padding 0/1/2/3 rejects; 4 accepts; upper bound rejects");
    return 0;
}
