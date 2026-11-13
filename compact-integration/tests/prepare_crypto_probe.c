/* SPDX-License-Identifier: GPL-2.0-only
 * Exercise the production path with MORE restrictive PKI-only authentication.
 * No production verification bypass or trust root is added. */
#define _GNU_SOURCE
#include "clamav.h"
static cl_error_t pki_only(const char *path,const char *certs,uint32_t options) {
    return cl_cvdverify_ex(path,certs,options|CL_DB_FIPS_LIMITS);
}
#define cl_cvdverify_ex pki_only
#include "../native/prepare.c"
#undef cl_cvdverify_ex
int main(int argc,char **argv) {
    if(argc!=3)return 2;
    return ci_prepare_generation_with_line_limit(argv[1],argv[2],131072);
}
