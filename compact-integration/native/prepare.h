/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef CI_PREPARE_H
#define CI_PREPARE_H
#include <stdint.h>

/* Prepare generation/profile from generation/databases. Emits one protocol-1
 * JSON result. Success inventories signed inputs; it does not certify native
 * syntax, bounded full-load equivalence, coverage, or automatic release. */
int ci_prepare_generation(const char *generation, const char *certs);
int ci_prepare_generation_with_line_limit(const char *generation,
                                         const char *certs,
                                         uint64_t max_line_bytes);

#endif
