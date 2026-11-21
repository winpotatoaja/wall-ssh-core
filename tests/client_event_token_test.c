#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "client_event_token.h"

int main(void) {
    uint64_t decoded = 0;
    assert(client_event_token_encode(0) == 0);
    assert(client_event_token_encode(CLIENT_EVENT_ID_MASK + UINT64_C(1)) == 0);

    const uint64_t ids[] = {
        UINT64_C(1), UINT64_C(2), UINT64_C(0x7fffffff),
        UINT64_C(0xffffffff), CLIENT_EVENT_ID_MASK
    };
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        uint64_t token = client_event_token_encode(ids[i]);
        assert(token != 0);
        assert(client_event_token_decode(token, &decoded) == 1);
        assert(decoded == ids[i]);
    }

    /* Pointer-valued listener/upstream entries must never decode as clients. */
    assert(client_event_token_decode(UINT64_C(0), &decoded) == 0);
    assert(client_event_token_decode(UINT64_C(0x7fffffff), &decoded) == 0);
    assert(client_event_token_decode(UINT64_C(0x00007fffffffffff), &decoded) == 0);
    assert(client_event_token_decode(CLIENT_EVENT_TAG, &decoded) == 0);
    puts("PASS client event token encode/decode and reserved values");
    return 0;
}
