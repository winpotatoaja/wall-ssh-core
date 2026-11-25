#include "chacha_runtime_config.h"
#include <stdio.h>
#define CHECK(ok, label) do { if(!(ok)) { fprintf(stderr,"FAIL: %s\n",label); return 1; } puts("PASS: " label); } while(0)
int main(void)
{
    static const char *vw[]={"auto","0","1","2","3"};
    static const int ew[]={-1,0,1,2,3};
    static const char *iw[]={"","AUTO","-1","4","01","1 ","3x"};
    static const char *vt[]={"4","8","16","24","32"};
    static const unsigned int et[]={4U,8U,16U,24U,32U};
    static const char *it[]={"","0","3","5","12","20","31","33","04","8K"};
    size_t i; int w; unsigned int k;
    for(i=0;i<5U;i++){w=99; CHECK(passwall_chacha_parse_workers(vw[i],&w)==0&&w==ew[i],"valid worker value accepted");}
    for(i=0;i<sizeof(iw)/sizeof(iw[0]);i++){w=99; CHECK(passwall_chacha_parse_workers(iw[i],&w)!=0&&w==99,"invalid worker value rejected");}
    for(i=0;i<5U;i++){k=0; CHECK(passwall_chacha_parse_threshold_kib(vt[i],&k)==0&&k==et[i],"valid threshold accepted"); CHECK(passwall_chacha_threshold_valid_bytes(k*1024U),"threshold maps to supported bytes");}
    for(i=0;i<sizeof(it)/sizeof(it[0]);i++){k=77U; CHECK(passwall_chacha_parse_threshold_kib(it[i],&k)!=0&&k==77U,"invalid threshold rejected");}
    CHECK(!passwall_chacha_threshold_valid_bytes(0U)&&!passwall_chacha_threshold_valid_bytes(4097U),"unsupported byte thresholds rejected");
    puts("PASS: R62 strict runtime configuration parser"); return 0;
}
