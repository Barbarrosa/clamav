#include "default.h"
#include "matcher-ac.h"
#include "mpool.h"
#include <stdio.h>
int main(void){struct cli_matcher r={0};struct cli_ac_data d;const char *n=0;cl_init(CL_INIT_DEFAULT);r.mempool=mpool_create();r.ac_only=1;cli_ac_init(&r,2,3,1);printf("load %d\n",cli_ac_addsig(&r,"Bounds","(6162|63646566)676869",0,0,0,0,0,0,0,0,"0",NULL,0));cli_ac_buildtrie(&r);cli_ac_initdata(&d,0,0,0,CLI_DEFAULT_AC_TRACKLEN);printf("short %d long %d\n",cli_ac_scanbuff((const unsigned char *)"abghi",5,&n,NULL,NULL,&r,&d,0,0,NULL,AC_SCAN_VIR,NULL),cli_ac_scanbuff((const unsigned char *)"cdefghi",7,&n,NULL,NULL,&r,&d,0,0,NULL,AC_SCAN_VIR,NULL));cli_ac_freedata(&d);cli_ac_free(&r);mpool_destroy(r.mempool);return 0;}