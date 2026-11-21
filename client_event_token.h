#ifndef CLIENT_EVENT_TOKEN_H
#define CLIENT_EVENT_TOKEN_H

#include <stdint.h>

#define CLIENT_EVENT_TAG     (UINT64_C(1) << 63)
#define CLIENT_EVENT_ID_MASK (CLIENT_EVENT_TAG - UINT64_C(1))

/* Zero is reserved as invalid; the high bit distinguishes client cookies
 * from the pointer-valued listener/upstream epoll entries. */
static inline uint64_t client_event_token_encode(uint64_t client_id) {
    if (client_id == 0 || client_id > CLIENT_EVENT_ID_MASK) return 0;
    return CLIENT_EVENT_TAG | client_id;
}

static inline int client_event_token_decode(uint64_t token, uint64_t *client_id_out) {
    if ((token & CLIENT_EVENT_TAG) == 0) return 0;
    uint64_t client_id = token & CLIENT_EVENT_ID_MASK;
    if (client_id == 0) return 0;
    if (client_id_out) *client_id_out = client_id;
    return 1;
}

#endif
