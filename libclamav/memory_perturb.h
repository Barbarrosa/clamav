/* SPDX-License-Identifier: GPL-2.0-only
 * Opt-in research allocation perturbation. No per-object metadata is added.
 */
#ifndef CLAMAV_MEMORY_PERTURB_H
#define CLAMAV_MEMORY_PERTURB_H

#include <stddef.h>
#include <stdlib.h>
#include "mpool.h"

#ifdef CM_MEMORY_PERTURB
/* Private integration ABI; snapshots append JSONL to CM_PAD_LOG. */
void cm_perturb_snapshot(const char *label);
struct cl_engine;
int cm_perturb_pool_stats(const struct cl_engine *engine, size_t *carved, size_t *mapped);
void *cm_perturb_malloc(const char *group, size_t size);
void *cm_perturb_calloc(const char *group, size_t count, size_t size);
void *cm_perturb_realloc(const char *group, void *ptr, size_t size);

/* Internal request accounting shared by heap and pool wrappers. added is zero
 * when the group is not selected. Exhausting the cap refuses the allocation. */
int cm_perturb_prepare(const char *group, size_t requested, size_t *physical, size_t *added);
void cm_perturb_finish(const char *group, void *ptr, size_t requested, size_t added);
void cm_perturb_reject_overflow(const char *group);

#define CM_PERTURB_MALLOC(group, size) cm_perturb_malloc((group), (size))
#define CM_PERTURB_CALLOC(group, count, size) cm_perturb_calloc((group), (count), (size))
#define CM_PERTURB_REALLOC(group, ptr, size) cm_perturb_realloc((group), (ptr), (size))
#ifdef USE_MPOOL
void *cm_mpool_malloc(const char *group, mpool_t *mp, size_t size);
void *cm_mpool_calloc(const char *group, mpool_t *mp, size_t count, size_t size);
void *cm_mpool_realloc(const char *group, mpool_t *mp, void *ptr, size_t size);
void *cm_mpool_realloc2(const char *group, mpool_t *mp, void *ptr, size_t size);
char *cm_mpool_strdup(const char *group, mpool_t *mp, const char *value);
#define CM_MPOOL_MALLOC(group, mp, size) cm_mpool_malloc((group), (mp), (size))
#define CM_MPOOL_CALLOC(group, mp, count, size) cm_mpool_calloc((group), (mp), (count), (size))
#define CM_MPOOL_REALLOC(group, mp, ptr, size) cm_mpool_realloc((group), (mp), (ptr), (size))
#define CM_MPOOL_REALLOC2(group, mp, ptr, size) cm_mpool_realloc2((group), (mp), (ptr), (size))
#define CM_MPOOL_STRDUP(group, mp, value) cm_mpool_strdup((group), (mp), (value))
#else
#define CM_MPOOL_MALLOC(group, mp, size) CM_PERTURB_MALLOC((group), (size))
#define CM_MPOOL_CALLOC(group, mp, count, size) CM_PERTURB_CALLOC((group), (count), (size))
#define CM_MPOOL_REALLOC(group, mp, ptr, size) CM_PERTURB_REALLOC((group), (ptr), (size))
/* The non-pool realloc2 path retains its original helper semantics. */
#define CM_MPOOL_REALLOC2(group, mp, ptr, size) MPOOL_REALLOC2((mp), (ptr), (size))
#define CM_MPOOL_STRDUP(group, mp, value) CLI_MPOOL_STRDUP((mp), (value))
#endif
#else
#define CM_PERTURB_MALLOC(group, size) malloc(size)
#define CM_PERTURB_CALLOC(group, count, size) calloc((count), (size))
#define CM_PERTURB_REALLOC(group, ptr, size) realloc((ptr), (size))
#define CM_MPOOL_MALLOC(group, mp, size) MPOOL_MALLOC((mp), (size))
#define CM_MPOOL_CALLOC(group, mp, count, size) MPOOL_CALLOC((mp), (count), (size))
#define CM_MPOOL_REALLOC(group, mp, ptr, size) MPOOL_REALLOC((mp), (ptr), (size))
#define CM_MPOOL_REALLOC2(group, mp, ptr, size) MPOOL_REALLOC2((mp), (ptr), (size))
#define CM_MPOOL_STRDUP(group, mp, value) CLI_MPOOL_STRDUP((mp), (value))
#endif

#endif
