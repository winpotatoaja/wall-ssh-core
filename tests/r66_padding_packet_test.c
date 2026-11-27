#include <stddef.h>
#include <stdio.h>

static int ssh_padding_valid(size_t padding, size_t packet_length)
{
    return packet_length > 0U &&
           padding >= 4U &&
           padding <= packet_length - 1U;
}

int main(void)
{
    const size_t packet_length = 32U;
    size_t padding;

    if(ssh_padding_valid(0U, 0U) || ssh_padding_valid(4U, 0U) ||
       ssh_padding_valid(0U, 1U) || ssh_padding_valid(4U, 4U)) {
        fprintf(stderr, "FAIL: zero or undersized packet length was accepted\n");
        return 1;
    }
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
    if(!ssh_padding_valid(packet_length - 1U, packet_length))
        return 1;
    if(ssh_padding_valid(packet_length, packet_length)) {
        fprintf(stderr, "FAIL: upper padding bound was accepted\n");
        return 1;
    }

    puts("PASS: SSH padding 0/1/2/3 rejects; 4 accepts; zero length and upper bound reject");
    return 0;
}
