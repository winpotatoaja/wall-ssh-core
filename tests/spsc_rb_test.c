#define _GNU_SOURCE
#include "../spsc_rb.h"
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#define CAPACITY 32768U
#define TOTAL_BYTES (16U*1024U*1024U)
#define CHECK(c,m) do{if(!(c)){fprintf(stderr,"FAIL: %s errno=%d\n",m,errno);return 1;}}while(0)
typedef struct{spsc_rb_t*q;uint64_t total;int failed;} stress_t;
static uint8_t byte_at(uint64_t n){uint64_t x=n*UINT64_C(0x9e3779b185ebca87);x^=x>>29;x^=x>>17;return(uint8_t)(x^(x>>8)^(x>>24));}
static uint32_t rnd_next(uint32_t*s){uint32_t x=*s;x^=x<<13;x^=x>>17;x^=x<<5;*s=x;return x;}
static int test_basic(void){
 spsc_rb_t q;CHECK(spsc_rb_init(&q,0U)!=0,"reject zero capacity");
 CHECK(spsc_rb_init(&q,3U)!=0,"reject non-power-of-two");
 CHECK(spsc_rb_init(&q,1U<<31)!=0,"reject >2^30 capacity");
 CHECK(spsc_rb_init(&q,8U)==0,"init basic ring");
 size_t n=0;uint32_t t=0;uint8_t*w=spsc_rb_write_span(&q,&n,&t);
 CHECK(w&&n==8U&&t==0U,"initial write span");memcpy(w,"01234567",8);
 CHECK(spsc_rb_commit_write(&q,t,8)==0,"commit full ring");
 CHECK(spsc_rb_write_span(&q,&n,&t)==NULL&&n==0,"full ring");
 const uint8_t*r=spsc_rb_read_span(&q,&n,&t);
 CHECK(r&&n==8&&memcmp(r,"01234567",8)==0,"read full ring");
 CHECK(spsc_rb_commit_read(&q,t,5)==0,"partial read");
 w=spsc_rb_write_span(&q,&n,&t);CHECK(w&&n==5,"wrapped write span");
 memcpy(w,"abcde",5);CHECK(spsc_rb_commit_write(&q,t,5)==0,"wrapped write commit");
 r=spsc_rb_read_span(&q,&n,&t);CHECK(r&&n==3&&memcmp(r,"567",3)==0,"first read segment");
 CHECK(spsc_rb_commit_read(&q,t,3)==0,"first read commit");
 r=spsc_rb_read_span(&q,&n,&t);CHECK(r&&n==5&&memcmp(r,"abcde",5)==0,"wrapped read segment");
 CHECK(spsc_rb_commit_read(&q,t,5)==0,"drain ring");
 uint32_t h=__atomic_load_n(&q.head.value,__ATOMIC_RELAXED),z=__atomic_load_n(&q.tail.value,__ATOMIC_RELAXED);
 CHECK(h==z&&h==13U,"empty indices are not reset");spsc_rb_destroy(&q);
 CHECK(spsc_rb_init(&q,16U)==0,"init pinned ring");
 w=spsc_rb_write_span(&q,&n,&t);CHECK(w&&n>=8,"pinned write span");
 memcpy(w,"abcdefgh",8);CHECK(spsc_rb_commit_write(&q,t,8)==0,"pinned write commit");
 r=spsc_rb_read_span(&q,&n,&t);CHECK(r&&n>=8,"pinned read span");
 uint32_t rt=t;const uint8_t*p=spsc_rb_read_span_at(&q,rt,8);
 CHECK(p==r,"pinned pointer address");
 w=spsc_rb_write_span(&q,&n,&t);CHECK(w&&n>=4,"append while pinned");
 memcpy(w,"ijkl",4);CHECK(spsc_rb_commit_write(&q,t,4)==0,"append commit");
 CHECK(spsc_rb_read_span_at(&q,rt,8)==p&&memcmp(p,"abcdefgh",8)==0,"pinned bytes stable");
 CHECK(spsc_rb_commit_read(&q,rt,8)==0,"pinned consume");spsc_rb_destroy(&q);return 0;
}
static void*producer(void*arg){
 static const size_t chunks[]={1,7,513,4093};stress_t*c=arg;uint64_t pos=0;uint32_t rnd=0x1234abcdU;
 while(pos<c->total&&!__atomic_load_n(&c->failed,__ATOMIC_ACQUIRE)){
  size_t n=0;uint32_t t=0;uint8_t*p=spsc_rb_write_span(c->q,&n,&t);
  if(!p||!n){sched_yield();continue;}size_t k=chunks[rnd_next(&rnd)&3U];
  if(k>n)k=n;if((uint64_t)k>c->total-pos)k=(size_t)(c->total-pos);
  for(size_t i=0;i<k;i++)p[i]=byte_at(pos+i);
  if(spsc_rb_commit_write(c->q,t,k)!=0){__atomic_store_n(&c->failed,1,__ATOMIC_RELEASE);break;}pos+=k;
 }return NULL;
}
static void*consumer(void*arg){
 static const size_t chunks[]={7,1,4093,513};stress_t*c=arg;uint64_t pos=0;uint32_t rnd=0x87654321U;
 while(pos<c->total&&!__atomic_load_n(&c->failed,__ATOMIC_ACQUIRE)){
  size_t n=0;uint32_t t=0;const uint8_t*p=spsc_rb_read_span(c->q,&n,&t);
  if(!p||!n){sched_yield();continue;}size_t k=chunks[rnd_next(&rnd)&3U];
  if(k>n)k=n;if((uint64_t)k>c->total-pos)k=(size_t)(c->total-pos);
  for(size_t i=0;i<k;i++)if(p[i]!=byte_at(pos+i)){fprintf(stderr,"byte mismatch at %llu\n",(unsigned long long)(pos+i));__atomic_store_n(&c->failed,1,__ATOMIC_RELEASE);return NULL;}
  if(spsc_rb_commit_read(c->q,t,k)!=0){__atomic_store_n(&c->failed,1,__ATOMIC_RELEASE);break;}pos+=k;
 }return NULL;
}
static int stress(uint32_t initial,const char*name){
 spsc_rb_t q;CHECK(spsc_rb_init(&q,CAPACITY)==0,"init stress queue");
 __atomic_store_n(&q.head.value,initial,__ATOMIC_RELAXED);__atomic_store_n(&q.tail.value,initial,__ATOMIC_RELAXED);
 stress_t c={.q=&q,.total=TOTAL_BYTES,.failed=0};pthread_t p,t;
 int rc=pthread_create(&p,NULL,producer,&c);CHECK(rc==0,"create producer");
 rc=pthread_create(&t,NULL,consumer,&c);
 if(rc!=0){__atomic_store_n(&c.failed,1,__ATOMIC_RELEASE);pthread_join(p,NULL);spsc_rb_destroy(&q);errno=rc;return 1;}
 pthread_join(p,NULL);pthread_join(t,NULL);
 CHECK(!__atomic_load_n(&c.failed,__ATOMIC_ACQUIRE),"stress byte integrity");
 uint32_t h=__atomic_load_n(&q.head.value,__ATOMIC_RELAXED),z=__atomic_load_n(&q.tail.value,__ATOMIC_RELAXED);
 CHECK(h==z&&h==initial+(uint32_t)TOTAL_BYTES,"drained ring and counter rollover");
 spsc_rb_destroy(&q);printf("PASS: SPSC %s (%u bytes)\n",name,TOTAL_BYTES);return 0;
}
int main(void){
 if(test_basic()||stress(0U,"normal counters")||stress(UINT32_C(0xFFFFFF00),"uint32_t rollover"))return 1;
 puts("PASS: all SPSC ring tests");return 0;
}
