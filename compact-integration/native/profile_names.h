/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef CI_PROFILE_NAMES_H
#define CI_PROFILE_NAMES_H
#include <stdint.h>
#include <string.h>
/* Upstream uses <database>-<version>.cvd.sign for CVD and CLD transports. */
static inline int ci_official_signature_name(const char *name) {
    const char *p=NULL;
    if(!strncmp(name,"main-",5))p=name+5;
    else if(!strncmp(name,"daily-",6))p=name+6;
    else if(!strncmp(name,"bytecode-",9))p=name+9;
    if(!p||*p<'0'||*p>'9')return 0;
    uint64_t value=0;unsigned digits=0;
    while(*p>='0'&&*p<='9') {
        if(++digits>10)return 0;
        value=value*10+(unsigned)(*p++-'0');if(value>UINT32_MAX)return 0;
    }
    return !strcmp(p,".cvd.sign");
}
#endif
