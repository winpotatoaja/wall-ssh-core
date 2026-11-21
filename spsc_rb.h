#ifndef PASSWALL_SSH_CORE_SPSC_RB_H
#define PASSWALL_SSH_CORE_SPSC_RB_H
/* Standalone SPSC byte ring. Init/destroy require both sides to be stopped. */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define SPSC_RB_CACHELINE_STRIDE 64U
_Static_assert(sizeof(uint32_t)==4U,"SPSC counters require uint32_t");
_Static_assert(__atomic_always_lock_free(sizeof(uint32_t),0),
               "32-bit atomics must be lock-free on this target");
typedef struct { uint32_t value; unsigned char padding[60U]; } spsc_rb_index_t;
_Static_assert(sizeof(spsc_rb_index_t)==64U,"indices need separate cache-line strides");
typedef struct {
 spsc_rb_index_t head; /* consumer-owned */
 spsc_rb_index_t tail; /* producer-owned */
 uint8_t *data;
 uint32_t capacity,mask;
} spsc_rb_t;
_Static_assert(offsetof(spsc_rb_t,tail)-offsetof(spsc_rb_t,head)>=64U,
               "head and tail must not share a cache line");
/* Power-of-two capacity, 2 <= capacity <= 2^30. */
static inline int spsc_rb_init(spsc_rb_t *q,uint32_t capacity) {
 if(!q||capacity<2U||(capacity&(capacity-1U))||capacity>(1U<<30)){errno=EINVAL;return -1;}
 memset(q,0,sizeof(*q)); q->data=(uint8_t*)malloc((size_t)capacity);
 if(!q->data)return -1;
 q->capacity=capacity;q->mask=capacity-1U;
 __atomic_store_n(&q->head.value,0U,__ATOMIC_RELAXED);
 __atomic_store_n(&q->tail.value,0U,__ATOMIC_RELAXED);return 0;
}
/* Call only after producer and consumer have stopped. */
static inline void spsc_rb_destroy(spsc_rb_t *q) {
 if(!q)return;free(q->data);q->data=NULL;q->capacity=q->mask=0U;
 __atomic_store_n(&q->head.value,0U,__ATOMIC_RELAXED);
 __atomic_store_n(&q->tail.value,0U,__ATOMIC_RELAXED);
}
/* Producer-only: reserve a contiguous span and receive its tail ticket. */
static inline uint8_t *spsc_rb_write_span(spsc_rb_t *q,size_t *available,uint32_t *ticket) {
 if(available)*available=0U;if(ticket)*ticket=0U;
 if(!q||!q->data||!available||!ticket){errno=EINVAL;return NULL;}
 uint32_t tail=__atomic_load_n(&q->tail.value,__ATOMIC_RELAXED);
 uint32_t head=__atomic_load_n(&q->head.value,__ATOMIC_ACQUIRE);
 uint32_t used=(uint32_t)(tail-head);
 if(used>q->capacity){errno=EOVERFLOW;return NULL;}
 uint32_t free_bytes=q->capacity-used;if(!free_bytes)return NULL;
 uint32_t index=tail&q->mask,span=q->capacity-index;
 if(span>free_bytes)span=free_bytes;
 *available=(size_t)span;*ticket=tail;return q->data+index;
}
/* Producer-only: publish bytes after copying them into the reserved span. */
static inline int spsc_rb_commit_write(spsc_rb_t *q,uint32_t ticket,size_t length) {
 if(!q||!q->data||length>(size_t)q->capacity){errno=EINVAL;return -1;}
 uint32_t tail=__atomic_load_n(&q->tail.value,__ATOMIC_RELAXED);
 if(tail!=ticket){errno=EBUSY;return -1;}
 uint32_t head=__atomic_load_n(&q->head.value,__ATOMIC_ACQUIRE);
 uint32_t used=(uint32_t)(tail-head),index=tail&q->mask;
 if(used>q->capacity||length>(size_t)(q->capacity-used)||
    length>(size_t)(q->capacity-index)){errno=ENOSPC;return -1;}
 __atomic_store_n(&q->tail.value,tail+(uint32_t)length,__ATOMIC_RELEASE);return 0;
}
/* Consumer-only: acquire makes all bytes published by tail visible. */
static inline const uint8_t *spsc_rb_read_span(const spsc_rb_t *q,size_t *available,uint32_t *ticket) {
 if(available)*available=0U;if(ticket)*ticket=0U;
 if(!q||!q->data||!available||!ticket){errno=EINVAL;return NULL;}
 uint32_t head=__atomic_load_n(&q->head.value,__ATOMIC_RELAXED);
 uint32_t tail=__atomic_load_n(&q->tail.value,__ATOMIC_ACQUIRE);
 uint32_t used=(uint32_t)(tail-head);
 if(used>q->capacity){errno=EOVERFLOW;return NULL;}if(!used)return NULL;
 uint32_t index=head&q->mask,span=q->capacity-index;if(span>used)span=used;
 *available=(size_t)span;*ticket=head;return q->data+index;
}
/* Revalidate a pinned libssh2 write span after EAGAIN. Producer appends cannot
 * move head or overwrite unconsumed bytes, so the returned address is stable. */
static inline const uint8_t *spsc_rb_read_span_at(const spsc_rb_t *q,uint32_t ticket,size_t length) {
 if(!q||!q->data||!length||length>(size_t)q->capacity){errno=EINVAL;return NULL;}
 uint32_t head=__atomic_load_n(&q->head.value,__ATOMIC_RELAXED);
 if(head!=ticket){errno=ESTALE;return NULL;}
 uint32_t tail=__atomic_load_n(&q->tail.value,__ATOMIC_ACQUIRE);
 uint32_t used=(uint32_t)(tail-ticket),index=ticket&q->mask;
 if(used>q->capacity||length>(size_t)used||length>(size_t)(q->capacity-index)){errno=EINVAL;return NULL;}
 return q->data+index;
}
/* Consumer-only: head is never reset when the ring becomes empty. */
static inline int spsc_rb_commit_read(spsc_rb_t *q,uint32_t ticket,size_t length) {
 if(!q||!q->data||length>(size_t)q->capacity){errno=EINVAL;return -1;}
 uint32_t head=__atomic_load_n(&q->head.value,__ATOMIC_RELAXED);
 if(head!=ticket){errno=ESTALE;return -1;}
 uint32_t tail=__atomic_load_n(&q->tail.value,__ATOMIC_ACQUIRE);
 uint32_t used=(uint32_t)(tail-head),index=head&q->mask;
 if(used>q->capacity||length>(size_t)used||length>(size_t)(q->capacity-index)){errno=EINVAL;return -1;}
 __atomic_store_n(&q->head.value,head+(uint32_t)length,__ATOMIC_RELEASE);return 0;
}
#endif
