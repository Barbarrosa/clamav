/*
 *  Copyright (C) 2013-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */
#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <check.h>
#include <stdio.h>
#include <string.h>

// libclamav
#include "clamav.h"
#include "readdb.h"
#include "matcher.h"
#include "matcher-ac.h"
#include "matcher-bm.h"
#include "matcher-byte-comp.h"
#include "matcher-pcre.h"
#include "others.h"
#include "default.h"
#include "clamav_rust.h"

#include "checks.h"

static const struct ac_testdata_s {
    const char *data;
    const char *hexsig;
    const char *virname;
} ac_testdata[] = {
    /* IMPORTANT: ac_testdata[i].hexsig should only match ac_testdata[i].data */
    {"daaaaaaaaddbbbbbcce", "64[4-4]61616161{2}6262[3-6]65", "Test_1: anchored and ranged wildcard"},
    {"ebbbbbbbbeecccccddf", "6262(6162|6364|6265|6465){2}6363", "Test_2: multi-byte fixed alternate w/ ranged wild"},
    {"aaaabbbbcccccdddddeeee", "616161*63636363*6565", "Test_3: unbounded wildcards"},
    {"oprstuwxy", "6f??727374????7879", "Test_4: nibble wildcards"},
    {"abdcabcddabccadbbdbacb", "6463{2-3}64646162(63|64|65)6361*6462????6261{-1}6362", "Test_5: various wildcard combinations w/ alternate"},
    {"abcdefghijkabcdefghijk", "62????65666768*696a6b6162{2-3}656667[1-3]6b", "Test_6: various wildcard combinations"},
    {"abcadbabcadbabcacb", "6?6164?26?62{3}?26162?361", "Test_7: nibble and ranged wildcards"},
    /* testcase for filter bug: it was checking only first 32 chars, and last
     * maxpatlen */
    {"\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1dddddddddddddddddddd5\1\1\1\1\1\1\1\1\1\1\1\1\1", "6464646464646464646464646464646464646464(35|36)", "Test_8: filter bug"},

    /* altbyte */
    {"aabaa", "6161(62|63|64)6161", "Ac_Altstr_Test_1"}, /* control */
    {"aacaa", "6161(62|63|64)6161", "Ac_Altstr_Test_1"}, /* control */
    {"aadaa", "6161(62|63|64)6161", "Ac_Altstr_Test_1"}, /* control */

    /* alt-fstr */
    {"aabbbaa", "6161(626262|636363|646464)6161", "Ac_Altstr_Test_2"}, /* control */
    {"aacccaa", "6161(626262|636363|646464)6161", "Ac_Altstr_Test_2"}, /* control */
    {"aadddaa", "6161(626262|636363|646464)6161", "Ac_Altstr_Test_2"}, /* control */

    /* alt-vstr */
    {"aabbaa", "6161(6262|63636363|6464646464)6161", "Ac_Altstr_Test_3"},    /* control */
    {"aaccccaa", "6161(6262|63636363|6464646464)6161", "Ac_Altstr_Test_3"},  /* control */
    {"aadddddaa", "6161(6262|63636363|6464646464)6161", "Ac_Altstr_Test_3"}, /* control */

    /* alt-embed */
    {"aajjaa", "6161(6a6a|66(6767|6868)66|6969)6161", "Ac_Altstr_Test_4"},   /* control */
    {"aafggfaa", "6161(6a6a|66(6767|6868)66|6969)6161", "Ac_Altstr_Test_4"}, /* control */
    {"aafhhfaa", "6161(6a6a|66(6767|6868)66|6969)6161", "Ac_Altstr_Test_4"}, /* control */
    {"aaiiaa", "6161(6a6a|66(6767|6868)66|6969)6161", "Ac_Altstr_Test_4"},   /* control */

    {NULL, NULL, NULL}};

static const struct ac_sigopts_testdata_s {
    const char *data;
    uint32_t dlength;
    const char *hexsig;
    const char *offset;
    const uint16_t sigopts;
    const char *virname;
    const uint8_t expected_result;
} ac_sigopts_testdata[] = {
    /* nocase */
    {"aaaaa", 5, "6161616161", "*", ACPATT_OPTION_NOOPTS, "AC_Sigopts_Test_1", CL_VIRUS}, /* control */
    {"bBbBb", 5, "6262626262", "*", ACPATT_OPTION_NOOPTS, "AC_Sigopts_Test_2", CL_CLEAN}, /* nocase control */
    {"cCcCc", 5, "6363636363", "*", ACPATT_OPTION_NOCASE, "AC_Sigopts_Test_3", CL_VIRUS}, /* nocase test */

    /* fullword */
    {"ddddd&e", 7, "6464646464", "*", ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_4", CL_VIRUS},   /* fullword start */
    {"s&eeeee&e", 9, "6565656565", "*", ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_5", CL_VIRUS}, /* fullword middle */
    {"s&fffff", 7, "6666666666", "*", ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_6", CL_VIRUS},   /* fullword end */
    {"sggggg", 6, "6767676767", "*", ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_7", CL_CLEAN},    /* fullword fail start */
    {"hhhhhe", 6, "6868686868", "*", ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_8", CL_CLEAN},    /* fullword fail end */

    {"iiiii", 5, "(W)6969696969", "*", ACPATT_OPTION_NOOPTS, "AC_Sigopts_Test_9", CL_VIRUS},   /* fullword class start */
    {"jjj&jj", 6, "6a6a6a(W)6a6a", "*", ACPATT_OPTION_NOOPTS, "AC_Sigopts_Test_10", CL_VIRUS}, /* fullword class middle */
    {"kkkkk", 5, "6b6b6b6b6b(W)", "*", ACPATT_OPTION_NOOPTS, "AC_Sigopts_Test_11", CL_VIRUS},  /* fullword class end */
    {"slllll", 6, "(W)6c6c6c6c6c", "*", ACPATT_OPTION_NOOPTS, "AC_Sigopts_Test_12", CL_CLEAN}, /* fullword fail start */
    {"mmmmme", 6, "6d6d6d6d6d(W)", "*", ACPATT_OPTION_NOOPTS, "AC_Sigopts_Test_13", CL_CLEAN}, /* fullword class end */

    {"nNnNn", 5, "6e6e6e6e6e", "*", ACPATT_OPTION_NOCASE | ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_14", CL_VIRUS},  /* nocase fullword */
    {"soOoOo", 6, "6f6f6f6f6f", "*", ACPATT_OPTION_NOCASE | ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_15", CL_CLEAN}, /* nocase fullword start fail */
    {"pPpPpe", 6, "7070707070", "*", ACPATT_OPTION_NOCASE | ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_16", CL_CLEAN}, /* nocase fullword end fail */

    /* wide */
    {"q\0q\0q\0q\0q\0", 10, "7171717171", "*", ACPATT_OPTION_WIDE, "AC_Sigopts_Test_17", CL_VIRUS},                          /* control */
    {"r\0R\0r\0R\0r\0", 10, "7272727272", "*", ACPATT_OPTION_WIDE | ACPATT_OPTION_NOCASE, "AC_Sigopts_Test_18", CL_VIRUS},   /* control */
    {"s\0s\0s\0s\0s\0", 10, "7373737373", "*", ACPATT_OPTION_WIDE | ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_19", CL_VIRUS}, /* control */

    {"t\0t\0t\0t\0t\0", 10, "7474747474", "*", ACPATT_OPTION_WIDE | ACPATT_OPTION_ASCII, "AC_Sigopts_Test_20", CL_VIRUS}, /* control */

    {"u\0u\0u\0u\0u\0", 10, "7575757575", "*", ACPATT_OPTION_WIDE | ACPATT_OPTION_NOCASE | ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_21", CL_VIRUS}, /* control */
    {"v\0v\0v\0v\0v\0", 10, "7676767676", "*", ACPATT_OPTION_WIDE | ACPATT_OPTION_NOCASE | ACPATT_OPTION_ASCII, "AC_Sigopts_Test_22", CL_VIRUS},    /* control */

    {"w\0w\0w\0w\0w\0", 10, "7777777777", "*", ACPATT_OPTION_WIDE | ACPATT_OPTION_FULLWORD | ACPATT_OPTION_ASCII, "AC_Sigopts_Test_23", CL_VIRUS},                        /* control */
    {"x\0x\0x\0x\0x\0", 10, "7878787878", "*", ACPATT_OPTION_WIDE | ACPATT_OPTION_NOCASE | ACPATT_OPTION_FULLWORD | ACPATT_OPTION_ASCII, "AC_Sigopts_Test_24", CL_VIRUS}, /* control */

    {NULL, 0, NULL, NULL, ACPATT_OPTION_NOOPTS, NULL, CL_CLEAN}};

static const struct pcre_testdata_s {
    const char *data;
    const char *hexsig;
    const char *offset;
    const uint16_t sigopts;
    const char *virname;
    const uint8_t expected_result;
} pcre_testdata[] = {
    {"clamav", "/clamav/", "*", ACPATT_OPTION_NOOPTS, "Test_1: simple string", CL_VIRUS},
    {"cla:mav", "/cla:mav/", "*", ACPATT_OPTION_NOOPTS, "Test_2: embedded colon", CL_VIRUS},

    {"notbasic", "/basic/r", "0", ACPATT_OPTION_NOOPTS, "Test_3: rolling option", CL_VIRUS},
    {"nottrue", "/true/", "0", ACPATT_OPTION_NOOPTS, "Test4: rolling(off) option", CL_SUCCESS},

    {"not12345678truly", "/12345678/e", "3,8", ACPATT_OPTION_NOOPTS, "Test_5: encompass option", CL_VIRUS},
    {"not23456789truly", "/23456789/e", "4,8", ACPATT_OPTION_NOOPTS, "Test6: encompass option (low end)", CL_SUCCESS},
    {"not34567890truly", "/34567890/e", "3,7", ACPATT_OPTION_NOOPTS, "Test7: encompass option (high end)", CL_SUCCESS},

    {"notapietruly", "/apie/re", "2,2", ACPATT_OPTION_NOOPTS, "Test8: rolling encompass", CL_SUCCESS},
    {"notafigtruly", "/afig/e", "2,2", ACPATT_OPTION_NOOPTS, "Test9: rolling(off) encompass", CL_SUCCESS},
    {"notatretruly", "/atre/re", "2,6", ACPATT_OPTION_NOOPTS, "Test10: rolling encompass", CL_VIRUS},
    {"notasadtruly", "/asad/e", "2,6", ACPATT_OPTION_NOOPTS, "Test11: rolling(off) encompass", CL_VIRUS},

    {NULL, NULL, NULL, ACPATT_OPTION_NOOPTS, NULL, CL_CLEAN}};

static cli_ctx ctx;
static struct cl_scan_options options;

static fmap_t thefmap;
static const char *virname = NULL;
static void setup(void)
{
    struct cli_matcher *root;
    virname = NULL;

    memset(&thefmap, 0, sizeof(thefmap));

    memset(&ctx, 0, sizeof(ctx));
    memset(&options, 0, sizeof(struct cl_scan_options));
    ctx.options = &options;

    ctx.engine = cl_engine_new();
    ck_assert_msg(!!ctx.engine, "cl_engine_new() failed");

    ctx.dconf = ctx.engine->dconf;

    ctx.recursion_stack_size = ctx.engine->max_recursion_level;
    ctx.recursion_stack      = calloc(sizeof(cli_scan_layer_t), ctx.recursion_stack_size);
    ck_assert_msg(!!ctx.recursion_stack, "calloc() for recursion_stack failed");

    // ctx was memset, so recursion_level starts at 0.
    ctx.recursion_stack[ctx.recursion_level].fmap = &thefmap;

    ctx.fmap = ctx.recursion_stack[ctx.recursion_level].fmap;

    root = (struct cli_matcher *)MPOOL_CALLOC(ctx.engine->mempool, 1, sizeof(struct cli_matcher));
    ck_assert_msg(root != NULL, "root == NULL");
#ifdef USE_MPOOL
    root->mempool = ctx.engine->mempool;
#endif

    ctx.engine->root[0] = root;
}

static void teardown(void)
{
    cl_engine_free((struct cl_engine *)ctx.engine);
    if (ctx.recursion_stack[ctx.recursion_level].evidence) {
        evidence_free(ctx.recursion_stack[ctx.recursion_level].evidence);
    }
    free(ctx.recursion_stack);
}

START_TEST(test_ac_compact_lsig_state)
{
    struct cli_matcher root    = {0};
    struct cli_ac_lsig sigs[9] = {{0}};
    struct cli_ac_lsig *table[10];
    struct cli_bcomp_meta bytecomp     = {0};
    struct cli_bcomp_meta *bytecomps[] = {&bytecomp};
    struct cli_ac_data compact, independent, legacy;
#ifdef ENABLE_COMPACT_LSIG_STATE
    const unsigned widths[] = {1, 3, 64, 64, 64, 64, 64, 64, 64, 64};
#else
    const unsigned widths[] = {64, 64, 64, 64, 64, 64, 64, 64, 64, 64};
#endif
    uint32_t macro = 0;
    size_t slots = 0, pos = 0;
    unsigned i, j;

    for (i = 0; i < 9; i++) {
        table[i]     = &sigs[i];
        sigs[i].type = CLI_LSIG_NORMAL;
    }
    table[9]                = NULL;
    sigs[0].tdb.subsigs     = 1;
    sigs[1].tdb.subsigs     = 3;
    sigs[2].tdb.subsigs     = 64;
    sigs[3].tdb.subsigs     = 6;
    sigs[3].bc_idx          = 1;
    sigs[4].tdb.subsigs     = 4;
    sigs[4].type            = CLI_YARA_NORMAL;
    sigs[5].tdb.subsigs     = 2;
    sigs[5].tdb.macro_ptids = &macro;
    sigs[7].tdb.subsigs     = 65;
    sigs[8].tdb.subsigs     = 2;
    bytecomp.lsigid[0]      = 1;
    bytecomp.lsigid[1]      = 8;
    bytecomp.ref_subsigid   = 63;
    root.bcomp_metas        = 1;
    root.bcomp_metatable    = bytecomps;
    root.ac_lsigs           = 10;
    root.ac_lsigtable       = table;
#ifdef USE_MPOOL
    root.mempool = mpool_create();
    ck_assert_ptr_nonnull(root.mempool);
#endif
    ck_assert_int_eq(cli_ac_init(&root, 2, 3, 0), CL_SUCCESS);
    ck_assert_int_eq(cli_ac_buildtrie(&root), CL_SUCCESS);
    for (i = 0; i < 10; i++) {
#ifdef ENABLE_COMPACT_LSIG_STATE
        ck_assert_uint_eq((root.ac_lsig_offsets[i + 1] - root.ac_lsig_offsets[i]), widths[i]);
#else
        ck_assert_ptr_null(root.ac_lsig_offsets);
#endif
        slots += widths[i];
    }
#ifdef ENABLE_COMPACT_LSIG_STATE
    ck_assert_uint_eq(root.ac_lsig_slots, slots);
#endif
    ck_assert_int_eq(cli_ac_initdata_for_matcher(&compact, &root), CL_SUCCESS);
    ck_assert_int_eq(cli_ac_initdata_for_matcher(&independent, &root), CL_SUCCESS);
    ck_assert_int_eq(cli_ac_initdata(&legacy, 0, 10, 0, CLI_DEFAULT_AC_TRACKLEN), CL_SUCCESS);
    ck_assert_ptr_eq(compact.lsig_row_offsets, root.ac_lsig_offsets);
    ck_assert_ptr_eq(independent.lsig_row_offsets, root.ac_lsig_offsets);
    ck_assert_ptr_null(legacy.lsig_row_offsets);
    for (i = 0; i < 10; i++) {
        ck_assert_ptr_eq(cli_ac_lsig_counts(&compact, i), cli_ac_lsig_counts(&compact, 0) + pos);
        ck_assert_ptr_eq(cli_ac_lsig_first(&compact, i), cli_ac_lsig_first(&compact, 0) + pos);
        ck_assert_ptr_eq(cli_ac_lsig_last(&compact, i), cli_ac_lsig_last(&compact, 0) + pos);
        ck_assert_ptr_eq(cli_ac_lsig_counts(&legacy, i), cli_ac_lsig_counts(&legacy, 0) + i * 64);
        for (j = 0; j < widths[i]; j++) {
            ck_assert_uint_eq(cli_ac_lsig_counts(&compact, i)[j], 0);
            ck_assert_uint_eq(cli_ac_lsig_first(&compact, i)[j], CLI_OFF_NONE);
            ck_assert_uint_eq(cli_ac_lsig_last(&compact, i)[j], CLI_OFF_NONE);
        }
        /* Writing the end of one row must not overwrite the next row,
         * nor any state belonging to another scan of the same engine. */
        cli_ac_lsig_counts(&compact, i)[widths[i] - 1] = 100 + i;
        cli_ac_lsig_first(&compact, i)[widths[i] - 1]  = 200 + i;
        cli_ac_lsig_last(&compact, i)[widths[i] - 1]   = 300 + i;
        ck_assert_uint_eq(cli_ac_lsig_counts(&independent, i)[widths[i] - 1], 0);
        ck_assert_uint_eq(cli_ac_lsig_first(&independent, i)[widths[i] - 1], CLI_OFF_NONE);
        ck_assert_uint_eq(cli_ac_lsig_last(&independent, i)[widths[i] - 1], CLI_OFF_NONE);
        pos += widths[i];
    }
    cli_ac_freedata(&compact);
    cli_ac_freedata(&independent);
    cli_ac_freedata(&legacy);
    cli_ac_free(&root);
#ifdef USE_MPOOL
    mpool_destroy(root.mempool);
#endif
    ck_assert_int_eq(cli_ac_initdata_for_matcher(&compact, NULL), CL_SUCCESS);
    cli_ac_freedata(&compact);
    ck_assert_int_eq(cli_ac_buildtrie(NULL), CL_EMALFDB);
}
END_TEST

/* Run the same stateful matcher with compact and legacy storage. This checks
 * duplicate suppression, overlapping windows, suffix outputs, case folding,
 * wildcard verification, and the highest legal subsignature ID. */
START_TEST(test_ac_compact_scan_equivalence)
{
    static const unsigned widths[] = {1, 64, 3};
    static const struct {
        const char *hex;
        uint32_t lsig, subsig;
        uint8_t options;
    } patterns[] = {
        {"6162636465", 0, 0, 0},
        {"6162636465", 1, 63, 0},
        {"62636465", 2, 0, 0},
        {"6162636465", 2, 1, ACPATT_OPTION_NOCASE},
        {"6162??6465", 2, 2, 0},
    };
    static const unsigned char input[] = "abcde--ABCDE--abXde--abcde--bcde";
    struct cli_matcher *root           = ctx.engine->root[0];
    struct cli_ac_data compact, legacy;
    uint32_t ids[2];
    unsigned i, j, pass;

    ck_assert_int_eq(cli_ac_init(root, 2, 3, 0), CL_SUCCESS);
    root->ac_lsigtable = MPOOL_CALLOC(root->mempool, 3, sizeof(*root->ac_lsigtable));
    ck_assert_ptr_nonnull(root->ac_lsigtable);
    for (i = 0; i < 3; i++) {
        struct cli_ac_lsig *sig = MPOOL_CALLOC(root->mempool, 1, sizeof(*sig));
        ck_assert_ptr_nonnull(sig);
        sig->type                            = CLI_LSIG_NORMAL;
        sig->tdb.subsigs                     = widths[i];
        sig->id                              = i;
        root->ac_lsigtable[root->ac_lsigs++] = sig;
    }
    for (i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
        ids[0] = patterns[i].lsig;
        ids[1] = patterns[i].subsig;
        ck_assert_int_eq(cli_add_content_match_pattern(root, "CompactEquivalence", patterns[i].hex,
                                                       patterns[i].options, 0, 0, "*", ids, 0),
                         CL_SUCCESS);
    }
    ck_assert_int_eq(cli_ac_buildtrie(root), CL_SUCCESS);
#ifdef CLI_AC_FLAT_NODES
    ck_assert_ptr_nonnull(root->ac_flatnodes);
    ck_assert_ptr_eq(root->ac_root, root->ac_flatnodes + 1);
    ck_assert_ptr_null(root->ac_nodeidx);
    ck_assert_ptr_null(root->ac_buildpool);
    ck_assert_ptr_null(root->ac_nodetable);
    for (i = 1; i < root->ac_nodes + 2; i++) {
        const struct cli_ac_node *node = root->ac_flatnodes + i;
        if (node->fail) {
            uintptr_t fail = (uintptr_t)node->fail;
            ck_assert_msg(fail >= (uintptr_t)(root->ac_flatnodes + 1) &&
                              fail < (uintptr_t)(root->ac_flatnodes + root->ac_nodes + 2),
                          "failure pointer must reference the packed arena");
        }
        for (j = 0; j < 256; j++) {
            ck_assert_msg(node->trans[j] > 0 && node->trans[j] < root->ac_nodes + 2,
                          "completed transition must be a valid arena index");
        }
    }
#else
    ck_assert_ptr_null(root->ac_flatnodes);
    ck_assert_ptr_nonnull(root->ac_nodeidx);
#endif
    /* Every retained list link must refer to a list, never a discarded build
     * node, including the last member of a next_same chain. */
    for (i = 0; i < root->ac_lists; i++) {
        struct cli_ac_list *next = root->ac_listtable[i]->next;
        if (!next) continue;
        for (j = 0; j < root->ac_lists && root->ac_listtable[j] != next; j++) {
        }
        ck_assert_msg(j < root->ac_lists, "compiled list retained a construction pointer");
    }
    ck_assert_int_eq(cli_ac_initdata_for_matcher(&compact, root), CL_SUCCESS);
    ck_assert_int_eq(cli_ac_initdata(&legacy, root->ac_partsigs, root->ac_lsigs,
                                     root->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN),
                     CL_SUCCESS);
    for (pass = 0; pass < 4; pass++) {
        /* Repeat the first window, then overlap it, then advance. */
        uint32_t offset = pass < 2 ? 0 : (pass == 2 ? 7 : 100);
        ck_assert_int_eq(cli_ac_scanbuff(input, sizeof(input) - 1, NULL, NULL, NULL,
                                         root, &compact, offset, 0, NULL, AC_SCAN_VIR, NULL),
                         CL_CLEAN);
        ck_assert_int_eq(cli_ac_scanbuff(input, sizeof(input) - 1, NULL, NULL, NULL,
                                         root, &legacy, offset, 0, NULL, AC_SCAN_VIR, NULL),
                         CL_CLEAN);
        for (i = 0; i < 3; i++) {
            for (j = 0; j < widths[i]; j++) {
                ck_assert_uint_eq(cli_ac_lsig_counts(&compact, i)[j], cli_ac_lsig_counts(&legacy, i)[j]);
                ck_assert_uint_eq(cli_ac_lsig_first(&compact, i)[j], cli_ac_lsig_first(&legacy, i)[j]);
                ck_assert_uint_eq(cli_ac_lsig_last(&compact, i)[j], cli_ac_lsig_last(&legacy, i)[j]);
            }
        }
    }
    ck_assert_uint_gt(cli_ac_lsig_counts(&compact, 0)[0], 0);
    ck_assert_uint_eq(cli_ac_lsig_counts(&compact, 0)[0], cli_ac_lsig_counts(&compact, 1)[63]);
    ck_assert_uint_gt(cli_ac_lsig_counts(&compact, 2)[2], 0);

    /* Offsets keep their full uint32_t range, including zero and both
     * reserved values; the original update routine defines the semantics. */
    {
        const uint32_t offsets[] = {0, 0, 1, UINT32_MAX - 2, CLI_OFF_NONE, CLI_OFF_ANY};
        for (i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
            ck_assert_int_eq(lsig_sub_matched(root, &compact, 1, 63, offsets[i], i & 1), CL_SUCCESS);
            ck_assert_int_eq(lsig_sub_matched(root, &legacy, 1, 63, offsets[i], i & 1), CL_SUCCESS);
            ck_assert_uint_eq(cli_ac_lsig_counts(&compact, 1)[63], cli_ac_lsig_counts(&legacy, 1)[63]);
            ck_assert_uint_eq(cli_ac_lsig_last(&compact, 1)[63], cli_ac_lsig_last(&legacy, 1)[63]);
        }
    }
    cli_ac_freedata(&compact);
    cli_ac_freedata(&legacy);
    cli_ac_freedata(&compact); /* Cleanup is safe after partial/complete cleanup. */
}
END_TEST

START_TEST(test_ac_logical_pattern_does_not_keep_borrowed_virname)
{
    struct cli_matcher *root;
    uint32_t lsigid[2]      = {0, 0};
    char borrowed_virname[] = "Test.Logical.Signature";
    cl_error_t status;

    root = ctx.engine->root[0];
    ck_assert_msg(root != NULL, "root == NULL");

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    status = cli_ac_init(root, CLI_DEFAULT_AC_MINDEPTH, CLI_DEFAULT_AC_MAXDEPTH, 1);
    ck_assert_msg(status == CL_SUCCESS, "cli_ac_init() failed");
    ck_assert_msg(root->filter != NULL, "prefilter was not initialized");

    status = cli_add_content_match_pattern(root, borrowed_virname, "deadbeef",
                                           ACPATT_OPTION_NOOPTS, 0, 0, "EOF-0", lsigid, 0);
    ck_assert_msg(status == CL_SUCCESS, "cli_add_content_match_pattern() failed");
    ck_assert_uint_eq(root->ac_patterns, 1);
    ck_assert_msg(root->ac_pattable[0]->lsigid[0] == 1,
                  "pattern was not recorded as a logical subsignature");
    ck_assert_ptr_null(root->ac_pattable[0]->virname);
}
END_TEST

START_TEST(test_ac_compact_allocation_boundaries)
{
    struct cli_matcher *root   = ctx.engine->root[0];
    struct cli_ac_data partial = {0};
    cl_error_t status;

    ck_assert_int_eq(cli_ac_init(root, 2, 3, 0), CL_SUCCESS);
    /* An unrepresentable next ID must fail before accessing the node table,
     * and the rejected pattern must not become owned by the trie. */
    root->ac_nodes = UINT32_MAX - 1;
    root->ac_only  = 1;
    status         = cli_add_content_match_pattern(root, "Overflow", "61626364", 0, 0, 0, "*", NULL, 0);
    root->ac_nodes = 0;
    ck_assert_int_eq(status, CL_EMEM);
    ck_assert_uint_eq(root->ac_patterns, 0);

    /* Model failure after some, but not all, scan-state allocations. */
    partial.partsigs         = 4;
    partial.reloffsigs       = 2;
    partial.lsigs            = 2;
    partial.lsigcnt          = calloc(128, sizeof(*partial.lsigcnt));
    partial.lsigsuboff_first = calloc(128, sizeof(*partial.lsigsuboff_first));
    ck_assert_ptr_nonnull(partial.lsigcnt);
    ck_assert_ptr_nonnull(partial.lsigsuboff_first);
    cli_ac_freedata(&partial);
    ck_assert_ptr_null(partial.lsigcnt);
    ck_assert_uint_eq(partial.lsigs, 0);
    cli_ac_freedata(&partial);
    ck_assert_int_eq(cli_ac_initdata_for_matcher(NULL, root), CL_ENULLARG);
}
END_TEST

START_TEST(test_ac_scanbuff)
{
    struct cli_ac_data mdata;
    struct cli_matcher *root;
    unsigned int i;
    int ret;

    root = ctx.engine->root[0];
    ck_assert_msg(root != NULL, "root == NULL");
    root->ac_only = 1;

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_ac_init(root, CLI_DEFAULT_AC_MINDEPTH, CLI_DEFAULT_AC_MAXDEPTH, 1);
    ck_assert_msg(ret == CL_SUCCESS, "cli_ac_init() failed");

    for (i = 0; ac_testdata[i].data; i++) {
        ret = cli_add_content_match_pattern(root, ac_testdata[i].virname, ac_testdata[i].hexsig, 0, 0, 0, "*", NULL, 0);
        ck_assert_msg(ret == CL_SUCCESS, "cli_add_content_match_pattern failed");
    }

    ret = cli_ac_buildtrie(root);
    ck_assert_msg(ret == CL_SUCCESS, "cli_ac_buildtrie() failed");

    ret = cli_ac_initdata(&mdata, root->ac_partsigs, 0, 0, CLI_DEFAULT_AC_TRACKLEN);
    ck_assert_msg(ret == CL_SUCCESS, "cli_ac_initdata() failed");

    ctx.options->general &= ~CL_SCAN_GENERAL_ALLMATCHES; /* make sure all-match is disabled */
    for (i = 0; ac_testdata[i].data; i++) {
        ret = cli_ac_scanbuff((const unsigned char *)ac_testdata[i].data, strlen(ac_testdata[i].data), &virname, NULL, NULL, root, &mdata, 0, 0, NULL, AC_SCAN_VIR, NULL);
        ck_assert_msg(ret == CL_VIRUS, "cli_ac_scanbuff() failed for %s", ac_testdata[i].virname);
        ck_assert_msg(!strncmp(virname, ac_testdata[i].virname, strlen(ac_testdata[i].virname)), "Dataset %u matched with %s", i, virname);

        ret = cli_scan_buff((const unsigned char *)ac_testdata[i].data, strlen(ac_testdata[i].data), 0, &ctx, 0, NULL);
        ck_assert_msg(ret == CL_VIRUS, "cli_scan_buff() failed for %s", ac_testdata[i].virname);
        ck_assert_msg(!strncmp(virname, ac_testdata[i].virname, strlen(ac_testdata[i].virname)), "Dataset %u matched with %s", i, virname);
    }

    cli_ac_freedata(&mdata);
}
END_TEST

START_TEST(test_ac_repeated_prefix_does_not_shift_to_repeated_window)
{
    static const unsigned char data[] = {0xff, 0xff, 0xff, 0x00, 0x00, 0x00};
    struct cli_ac_data mdata;
    struct cli_ac_patt *pattern;
    struct cli_matcher *root;
    cl_error_t status;

    root = ctx.engine->root[0];
    ck_assert_msg(root != NULL, "root == NULL");
    root->ac_only = 1;

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    status = cli_ac_init(root, CLI_DEFAULT_AC_MINDEPTH, CLI_DEFAULT_AC_MAXDEPTH, 1);
    ck_assert_msg(status == CL_SUCCESS, "cli_ac_init() failed");

    status = cli_add_content_match_pattern(root, "RepeatedPrefixTransition", "ffffff000000", 0, 0, 0, "*", NULL, 0);
    ck_assert_msg(status == CL_SUCCESS, "cli_add_content_match_pattern failed");
    ck_assert_uint_eq(root->ac_patterns, 1);

    pattern = root->ac_pattable[0];
    ck_assert_ptr_nonnull(pattern);
    ck_assert_uint_eq(pattern->prefix_length[0], 2);
    ck_assert_uint_eq(pattern->depth, CLI_DEFAULT_AC_MAXDEPTH);
    ck_assert_uint_eq(pattern->pattern[0] & 0xff, 0xff);
    ck_assert_uint_eq(pattern->pattern[1] & 0xff, 0x00);
    ck_assert_uint_eq(pattern->pattern[2] & 0xff, 0x00);

    status = cli_ac_buildtrie(root);
    ck_assert_msg(status == CL_SUCCESS, "cli_ac_buildtrie() failed");
    status = cli_ac_initdata(&mdata, root->ac_partsigs, 0, 0, CLI_DEFAULT_AC_TRACKLEN);
    ck_assert_msg(status == CL_SUCCESS, "cli_ac_initdata() failed");

    status = cli_ac_scanbuff(data, sizeof(data), &virname, NULL, NULL, root, &mdata, 0, 0, NULL, AC_SCAN_VIR, NULL);
    ck_assert_msg(status == CL_VIRUS, "cli_ac_scanbuff() failed");
    ck_assert_msg(!strncmp(virname, "RepeatedPrefixTransition", strlen("RepeatedPrefixTransition")), "Incorrect signature matched in cli_ac_scanbuff()\n");

    cli_ac_freedata(&mdata);
}
END_TEST

START_TEST(test_ac_scanbuff_allscan)
{
    struct cli_ac_data mdata;
    struct cli_matcher *root;
    unsigned int i;
    int ret;

    root = ctx.engine->root[0];
    ck_assert_msg(root != NULL, "root == NULL");
    root->ac_only = 1;

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_ac_init(root, CLI_DEFAULT_AC_MINDEPTH, CLI_DEFAULT_AC_MAXDEPTH, 1);
    ck_assert_msg(ret == CL_SUCCESS, "cli_ac_init() failed");

    for (i = 0; ac_testdata[i].data; i++) {
        ret = cli_add_content_match_pattern(root, ac_testdata[i].virname, ac_testdata[i].hexsig, 0, 0, 0, "*", NULL, 0);
        ck_assert_msg(ret == CL_SUCCESS, "cli_add_content_match_pattern failed");
    }

    ret = cli_ac_buildtrie(root);
    ck_assert_msg(ret == CL_SUCCESS, "cli_ac_buildtrie() failed");

    ret = cli_ac_initdata(&mdata, root->ac_partsigs, 0, 0, CLI_DEFAULT_AC_TRACKLEN);
    ck_assert_msg(ret == CL_SUCCESS, "cli_ac_initdata() failed");

    ctx.options->general |= CL_SCAN_GENERAL_ALLMATCHES; /* enable all-match */
    for (i = 0; ac_testdata[i].data; i++) {
        ret = cli_ac_scanbuff((const unsigned char *)ac_testdata[i].data, strlen(ac_testdata[i].data), &virname, NULL, NULL, root, &mdata, 0, 0, NULL, AC_SCAN_VIR, NULL);
        ck_assert_msg(ret == CL_VIRUS, "cli_ac_scanbuff() failed for %s", ac_testdata[i].virname);
        ck_assert_msg(!strncmp(virname, ac_testdata[i].virname, strlen(ac_testdata[i].virname)), "Dataset %u matched with %s", i, virname);

        ret = cli_scan_buff((const unsigned char *)ac_testdata[i].data, strlen(ac_testdata[i].data), 0, &ctx, 0, NULL);
        ck_assert_msg(ret == CL_SUCCESS, "cli_scan_buff() failed for %s", ac_testdata[i].virname);

        // phishingScan() doesn't check the number of alerts. When using CL_SCAN_GENERAL_ALLMATCHES
        // or if using `CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE` and `cli_append_potentially_unwanted()`
        // we need to count the number of alerts manually to determine the verdict.
        ck_assert_msg(0 < evidence_num_alerts(ctx.this_layer_evidence), "cli_scan_buff() failed for %s", ac_testdata[i].virname);
        ck_assert_msg(!strncmp(virname, ac_testdata[i].virname, strlen(ac_testdata[i].virname)), "Dataset %u matched with %s", i, virname);
        if (evidence_num_alerts(ctx.this_layer_evidence) > 0) {
            // Reset evidence for the next scan.
            evidence_free(ctx.recursion_stack[ctx.recursion_level].evidence);
            ctx.recursion_stack[ctx.recursion_level].evidence = NULL;
            ctx.this_layer_evidence                           = NULL;
        }
    }

    cli_ac_freedata(&mdata);
}
END_TEST

START_TEST(test_ac_scanbuff_ex)
{
    struct cli_ac_data mdata;
    struct cli_matcher *root;
    unsigned int i;
    int ret;

    root = ctx.engine->root[0];
    ck_assert_msg(root != NULL, "root == NULL");
    root->ac_only = 1;

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_ac_init(root, CLI_DEFAULT_AC_MINDEPTH, CLI_DEFAULT_AC_MAXDEPTH, 1);
    ck_assert_msg(ret == CL_SUCCESS, "[ac_ex] cli_ac_init() failed");

    for (i = 0; ac_sigopts_testdata[i].data; i++) {
        ret = cli_sigopts_handler(root, ac_sigopts_testdata[i].virname, ac_sigopts_testdata[i].hexsig, ac_sigopts_testdata[i].sigopts, 0, 0, ac_sigopts_testdata[i].offset, NULL, 0);
        ck_assert_msg(ret == CL_SUCCESS, "[ac_ex] cli_sigopts_handler() failed");
    }

    ret = cli_ac_buildtrie(root);
    ck_assert_msg(ret == CL_SUCCESS, "[ac_ex] cli_ac_buildtrie() failed");

    ret = cli_ac_initdata(&mdata, root->ac_partsigs, 0, 0, CLI_DEFAULT_AC_TRACKLEN);
    ck_assert_msg(ret == CL_SUCCESS, "[ac_ex] cli_ac_initdata() failed");

    ctx.options->general &= ~CL_SCAN_GENERAL_ALLMATCHES; /* make sure all-match is disabled */
    for (i = 0; ac_sigopts_testdata[i].data; i++) {
        ret = cli_ac_scanbuff((const unsigned char *)ac_sigopts_testdata[i].data, ac_sigopts_testdata[i].dlength, &virname, NULL, NULL, root, &mdata, 0, 0, NULL, AC_SCAN_VIR, NULL);
        ck_assert_msg(ret == ac_sigopts_testdata[i].expected_result, "[ac_ex] cli_ac_scanbuff() failed for %s (%d != %d)", ac_sigopts_testdata[i].virname, ret, ac_sigopts_testdata[i].expected_result);
        if (ac_sigopts_testdata[i].expected_result == CL_VIRUS)
            ck_assert_msg(!strncmp(virname, ac_sigopts_testdata[i].virname, strlen(ac_sigopts_testdata[i].virname)), "[ac_ex] Dataset %u matched with %s", i, virname);

        ret = cli_scan_buff((const unsigned char *)ac_sigopts_testdata[i].data, ac_sigopts_testdata[i].dlength, 0, &ctx, 0, NULL);
        ck_assert_msg(ret == ac_sigopts_testdata[i].expected_result, "[ac_ex] cli_ac_scanbuff() failed for %s (%d != %d)", ac_sigopts_testdata[i].virname, ret, ac_sigopts_testdata[i].expected_result);
    }

    cli_ac_freedata(&mdata);
}
END_TEST

START_TEST(test_ac_scanbuff_allscan_ex)
{
    struct cli_ac_data mdata;
    struct cli_matcher *root;
    unsigned int i;
    int ret;

    root = ctx.engine->root[0];
    ck_assert_msg(root != NULL, "root == NULL");
    root->ac_only = 1;

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_ac_init(root, CLI_DEFAULT_AC_MINDEPTH, CLI_DEFAULT_AC_MAXDEPTH, 1);
    ck_assert_msg(ret == CL_SUCCESS, "[ac_ex] cli_ac_init() failed");

    for (i = 0; ac_sigopts_testdata[i].data; i++) {
        ret = cli_sigopts_handler(root, ac_sigopts_testdata[i].virname, ac_sigopts_testdata[i].hexsig, ac_sigopts_testdata[i].sigopts, 0, 0, ac_sigopts_testdata[i].offset, NULL, 0);
        ck_assert_msg(ret == CL_SUCCESS, "[ac_ex] cli_sigopts_handler() failed");
    }

    ret = cli_ac_buildtrie(root);
    ck_assert_msg(ret == CL_SUCCESS, "[ac_ex] cli_ac_buildtrie() failed");

    ret = cli_ac_initdata(&mdata, root->ac_partsigs, 0, 0, CLI_DEFAULT_AC_TRACKLEN);
    ck_assert_msg(ret == CL_SUCCESS, "[ac_ex] cli_ac_initdata() failed");

    ctx.options->general |= CL_SCAN_GENERAL_ALLMATCHES; /* enable all-match */
    for (i = 0; ac_sigopts_testdata[i].data; i++) {
        cl_error_t verdict = CL_CLEAN;

        ret = cli_ac_scanbuff((const unsigned char *)ac_sigopts_testdata[i].data, ac_sigopts_testdata[i].dlength, &virname, NULL, NULL, root, &mdata, 0, 0, NULL, AC_SCAN_VIR, NULL);
        ck_assert_msg(ret == ac_sigopts_testdata[i].expected_result, "[ac_ex] cli_ac_scanbuff() failed for %s (%d != %d)", ac_sigopts_testdata[i].virname, ret, ac_sigopts_testdata[i].expected_result);
        if (ac_sigopts_testdata[i].expected_result == CL_VIRUS)
            ck_assert_msg(!strncmp(virname, ac_sigopts_testdata[i].virname, strlen(ac_sigopts_testdata[i].virname)), "[ac_ex] Dataset %u matched with %s", i, virname);

        ret = cli_scan_buff((const unsigned char *)ac_sigopts_testdata[i].data, ac_sigopts_testdata[i].dlength, 0, &ctx, 0, NULL);
        ck_assert_msg(ret == CL_SUCCESS, "[ac_ex] cli_ac_scanbuff() failed for %s (%d != %d)", ac_sigopts_testdata[i].virname, ret, ac_sigopts_testdata[i].expected_result);

        // phishingScan() doesn't check the number of alerts. When using CL_SCAN_GENERAL_ALLMATCHES
        // or if using `CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE` and `cli_append_potentially_unwanted()`
        // we need to count the number of alerts manually to determine the verdict.
        if (0 < evidence_num_alerts(ctx.this_layer_evidence)) {
            verdict = CL_VIRUS;
        }

        ck_assert_msg(verdict == ac_sigopts_testdata[i].expected_result, "[ac_ex] cli_ac_scanbuff() failed for %s (%d != %d)", ac_sigopts_testdata[i].virname, verdict, ac_sigopts_testdata[i].expected_result);
        if (evidence_num_alerts(ctx.this_layer_evidence) > 0) {
            // Reset evidence for the next scan.
            evidence_free(ctx.recursion_stack[ctx.recursion_level].evidence);
            ctx.recursion_stack[ctx.recursion_level].evidence = NULL;
            ctx.this_layer_evidence                           = NULL;
        }
    }

    cli_ac_freedata(&mdata);
}
END_TEST

struct matcher_callback_state {
    unsigned calls;
    cl_error_t first_result;
};

static cl_error_t matcher_alert_callback(cl_scan_layer_t *layer, void *context)
{
    struct matcher_callback_state *state = context;
    (void)layer;
    return state->calls++ == 0 ? state->first_result : CL_VIRUS;
}

/* Exercise the complete matcher_run path so duplicate callback dispatch in
 * its caller is also detected. The first marker ends before the second starts,
 * making this independent of pointer-order tie breaking. */
START_TEST(test_matcher_nonterminal_indicators)
{
    static const char *names[] = {
        "Weak.First", "PUA.First", "Heuristics.First", "Ignored.First",
        "Break.First", "Trusted.First", "Weak.Only", "PUA.Only",
        "Strong.First", "PUA.Precedence"
    };
    static const char *patterns[] = {
        "41424344??464748", "41424344{1}464748", "4142434445464748"
    };
    static const unsigned char input[] = "ABCDEFGH--IJKLMNOP";
    unsigned matcher = _i / 10, scenario = _i % 10;
    struct cli_matcher *root = ctx.engine->root[0];
    struct matcher_callback_state state = {0, CL_VIRUS};
    cl_error_t expected = CL_VIRUS;
    unsigned length = sizeof(input) - 1, calls = 1;

    root->ac_only = matcher != 2;
    ck_assert_int_eq(cli_ac_init(root, 2, 3, 0), CL_SUCCESS);
    if (matcher == 2)
        ck_assert_int_eq(cli_bm_init(root), CL_SUCCESS);
    ck_assert_int_eq(cli_add_content_match_pattern(root, names[scenario], patterns[matcher],
                                                   0, 0, 0, "*", NULL, 0), CL_SUCCESS);
    ck_assert_int_eq(cli_add_content_match_pattern(root, "Strong.Second",
                                                   matcher == 2 ? "494a4b4c4d4e4f50" : "494a4b4c??4e4f50",
                                                   0, 0, 0, "*", NULL, 0), CL_SUCCESS);
    ck_assert_int_eq(cli_ac_buildtrie(root), CL_SUCCESS);
    cl_engine_set_scan_callback((struct cl_engine *)ctx.engine, matcher_alert_callback, CL_SCAN_CALLBACK_ALERT);
    ctx.cb_ctx = &state;

    if (scenario == 3) {
        state.first_result = CL_CLEAN;
        calls = 2;
    } else if (scenario == 4 || scenario == 5) {
        /* All-match must still honor an explicit stop/trust callback. */
        options.general |= CL_SCAN_GENERAL_ALLMATCHES;
        expected = state.first_result = scenario == 4 ? CL_BREAK : CL_VERIFIED;
    } else if (scenario == 6 || scenario == 7) {
        length = 8;
        expected = CL_SUCCESS;
        calls = 0;
    } else if (scenario == 9) {
        options.general |= CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE;
    }
    ck_assert_int_eq(cli_scan_buff(input, length, 0, &ctx, 0, NULL), expected);
    ck_assert_uint_eq(state.calls, calls);
    if (scenario <= 3) {
        ck_assert_str_eq(evidence_get_last_alert(ctx.this_layer_evidence), "Strong.Second.UNOFFICIAL");
        ck_assert_int_eq(ctx.recursion_stack[0].verdict, CL_VERDICT_STRONG_INDICATOR);
    } else if (scenario == 6) {
        ck_assert_ptr_null(evidence_get_last_alert(ctx.this_layer_evidence));
    } else if (scenario == 7 || scenario >= 8) {
        char expected_name[64];
        snprintf(expected_name, sizeof(expected_name), "%s.UNOFFICIAL", names[scenario]);
        ck_assert_str_eq(evidence_get_last_alert(ctx.this_layer_evidence), expected_name);
    }
}
END_TEST

START_TEST(test_ac_weak_hit_preserves_lsig_accounting)
{
    struct cli_matcher *root = ctx.engine->root[0];
    struct cli_ac_data data;
    uint32_t ids[] = {0, 0};
    static const unsigned char input[] = "ABCDEFGH--IJKLMNOP";
    root->ac_only = 1;
    ck_assert_int_eq(cli_ac_init(root, 2, 3, 0), CL_SUCCESS);
    root->ac_lsigtable = MPOOL_CALLOC(root->mempool, 1, sizeof(*root->ac_lsigtable));
    ck_assert_ptr_nonnull(root->ac_lsigtable);
    root->ac_lsigtable[0] = MPOOL_CALLOC(root->mempool, 1, sizeof(*root->ac_lsigtable[0]));
    ck_assert_ptr_nonnull(root->ac_lsigtable[0]);
    root->ac_lsigs = 1;
    root->ac_lsigtable[0]->tdb.subsigs = 1;
    root->ac_lsigtable[0]->type = CLI_LSIG_NORMAL;
    ck_assert_int_eq(cli_add_content_match_pattern(root, "Weak.First", "41424344??464748",
                                                   0, 0, 0, "*", NULL, 0), CL_SUCCESS);
    ck_assert_int_eq(cli_add_content_match_pattern(root, "Logical.Second", "494a4b4c??4e4f50",
                                                   0, 0, 0, "*", ids, 0), CL_SUCCESS);
    ck_assert_int_eq(cli_ac_buildtrie(root), CL_SUCCESS);
    ck_assert_int_eq(cli_ac_initdata(&data, 0, 1, 0, CLI_DEFAULT_AC_TRACKLEN), CL_SUCCESS);
    ck_assert_int_eq(cli_ac_scanbuff(input, sizeof(input) - 1, &virname, NULL, NULL,
                                     root, &data, 0, 0, NULL, AC_SCAN_VIR, &ctx), CL_SUCCESS);
    ck_assert_uint_eq(cli_ac_lsig_counts(&data, 0)[0], 1);
    ck_assert_uint_eq(cli_ac_lsig_first(&data, 0)[0], 10);
    cli_ac_freedata(&data);
}
END_TEST

START_TEST(test_bm_scanbuff)
{
    struct cli_matcher *root;
    const char *virname = NULL;
    int ret;

    root = ctx.engine->root[0];
    ck_assert_msg(root != NULL, "root == NULL");

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_bm_init(root);
    ck_assert_msg(ret == CL_SUCCESS, "cli_bm_init() failed");

    ret = cli_add_content_match_pattern(root, "Sig1", "deadbabe", 0, 0, 0, "*", NULL, 0);
    ck_assert_msg(ret == CL_SUCCESS, "cli_add_content_match_pattern failed");
    ret = cli_add_content_match_pattern(root, "Sig2", "deadbeef", 0, 0, 0, "*", NULL, 0);
    ck_assert_msg(ret == CL_SUCCESS, "cli_add_content_match_pattern failed");
    ret = cli_add_content_match_pattern(root, "Sig3", "babedead", 0, 0, 0, "*", NULL, 0);
    ck_assert_msg(ret == CL_SUCCESS, "cli_add_content_match_pattern failed");

    ctx.options->general &= ~CL_SCAN_GENERAL_ALLMATCHES; /* make sure all-match is disabled */
    ret = cli_bm_scanbuff((const unsigned char *)"blah\xde\xad\xbe\xef", 8, &virname, NULL, root, 0, NULL, NULL, NULL);
    ck_assert_msg(ret == CL_VIRUS, "cli_bm_scanbuff() failed");
    ck_assert_msg(!strncmp(virname, "Sig2", 4), "Incorrect signature matched in cli_bm_scanbuff()\n");
}
END_TEST

START_TEST(test_bm_scanbuff_allscan)
{
    struct cli_matcher *root;
    const char *virname = NULL;
    int ret;

    root = ctx.engine->root[0];
    ck_assert_msg(root != NULL, "root == NULL");

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_bm_init(root);
    ck_assert_msg(ret == CL_SUCCESS, "cli_bm_init() failed");

    ret = cli_add_content_match_pattern(root, "Sig1", "deadbabe", 0, 0, 0, "*", NULL, 0);
    ck_assert_msg(ret == CL_SUCCESS, "cli_add_content_match_pattern failed");
    ret = cli_add_content_match_pattern(root, "Sig2", "deadbeef", 0, 0, 0, "*", NULL, 0);
    ck_assert_msg(ret == CL_SUCCESS, "cli_add_content_match_pattern failed");
    ret = cli_add_content_match_pattern(root, "Sig3", "babedead", 0, 0, 0, "*", NULL, 0);
    ck_assert_msg(ret == CL_SUCCESS, "cli_add_content_match_pattern failed");

    ctx.options->general |= CL_SCAN_GENERAL_ALLMATCHES; /* enable all-match */
    ret = cli_bm_scanbuff((const unsigned char *)"blah\xde\xad\xbe\xef", 8, &virname, NULL, root, 0, NULL, NULL, NULL);
    ck_assert_msg(ret == CL_VIRUS, "cli_bm_scanbuff() failed");
    ck_assert_msg(!strncmp(virname, "Sig2", 4), "Incorrect signature matched in cli_bm_scanbuff()\n");
}
END_TEST

START_TEST(test_pcre_scanbuff)
{
    struct cli_ac_data mdata;
    struct cli_matcher *root;
    char *hexsig;
    unsigned int i, hexlen;
    int ret;

    root = ctx.engine->root[0];
    ck_assert_msg(root != NULL, "root == NULL");

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    for (i = 0; pcre_testdata[i].data; i++) {
        hexlen = strlen(PCRE_BYPASS) + strlen(pcre_testdata[i].hexsig) + 1;

        hexsig = calloc(hexlen, sizeof(char));
        ck_assert_msg(hexsig != NULL, "[pcre] failed to prepend bypass (out-of-memory)");

        strncat(hexsig, PCRE_BYPASS, hexlen);
        strncat(hexsig, pcre_testdata[i].hexsig, hexlen);

        ret = readdb_parse_ldb_subsignature(root, pcre_testdata[i].virname, hexsig, pcre_testdata[i].offset, NULL, 0, 0, 0, NULL);
        ck_assert_msg(ret == CL_SUCCESS, "[pcre] readdb_parse_ldb_subsignature failed");
        free(hexsig);
    }

    ret = cli_pcre_build(root, CLI_DEFAULT_PCRE_MATCH_LIMIT, CLI_DEFAULT_PCRE_RECMATCH_LIMIT, NULL);
    ck_assert_msg(ret == CL_SUCCESS, "[pcre] cli_pcre_build() failed");

    // recomputate offsets

    ret = cli_ac_initdata(&mdata, root->ac_partsigs, root->ac_lsigs, root->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN);
    ck_assert_msg(ret == CL_SUCCESS, "[pcre] cli_ac_initdata() failed");

    ctx.options->general &= ~CL_SCAN_GENERAL_ALLMATCHES; /* make sure all-match is disabled */
    for (i = 0; pcre_testdata[i].data; i++) {
        ret = cli_pcre_scanbuf((const unsigned char *)pcre_testdata[i].data, strlen(pcre_testdata[i].data), &virname, NULL, root, NULL, NULL, NULL);
        ck_assert_msg(ret == pcre_testdata[i].expected_result, "[pcre] cli_pcre_scanbuff() failed for %s (%d != %d)", pcre_testdata[i].virname, ret, pcre_testdata[i].expected_result);

        // we cannot check if the virname matches because we didn't load a whole logical signature, and virnames are stored in the lsig structure, now.

        ret = cli_scan_buff((const unsigned char *)pcre_testdata[i].data, strlen(pcre_testdata[i].data), 0, &ctx, 0, NULL);
        ck_assert_msg(ret == pcre_testdata[i].expected_result, "[pcre] cli_scan_buff() failed for %s", pcre_testdata[i].virname);
    }

    cli_ac_freedata(&mdata);
}
END_TEST

START_TEST(test_pcre_scanbuff_allscan)
{
    struct cli_ac_data mdata;
    struct cli_matcher *root;
    char *hexsig;
    unsigned int i, hexlen;
    int ret;

    root = ctx.engine->root[0];
    ck_assert_msg(root != NULL, "root == NULL");

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif

    for (i = 0; pcre_testdata[i].data; i++) {
        hexlen = strlen(PCRE_BYPASS) + strlen(pcre_testdata[i].hexsig) + 1;

        hexsig = calloc(hexlen, sizeof(char));
        ck_assert_msg(hexsig != NULL, "[pcre] failed to prepend bypass (out-of-memory)");

        strncat(hexsig, PCRE_BYPASS, hexlen);
        strncat(hexsig, pcre_testdata[i].hexsig, hexlen);

        ret = readdb_parse_ldb_subsignature(root, pcre_testdata[i].virname, hexsig, pcre_testdata[i].offset, NULL, 0, 0, 1, NULL);
        ck_assert_msg(ret == CL_SUCCESS, "[pcre] readdb_parse_ldb_subsignature failed");
        free(hexsig);
    }

    ret = cli_pcre_build(root, CLI_DEFAULT_PCRE_MATCH_LIMIT, CLI_DEFAULT_PCRE_RECMATCH_LIMIT, NULL);
    ck_assert_msg(ret == CL_SUCCESS, "[pcre] cli_pcre_build() failed");

    // recomputate offsets

    ret = cli_ac_initdata(&mdata, root->ac_partsigs, root->ac_lsigs, root->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN);
    ck_assert_msg(ret == CL_SUCCESS, "[pcre] cli_ac_initdata() failed");

    ctx.options->general |= CL_SCAN_GENERAL_ALLMATCHES; /* enable all-match */
    for (i = 0; pcre_testdata[i].data; i++) {
        cl_error_t verdict = CL_CLEAN;

        ret = cli_pcre_scanbuf((const unsigned char *)pcre_testdata[i].data, strlen(pcre_testdata[i].data), &virname, NULL, root, NULL, NULL, NULL);
        ck_assert_msg(ret == pcre_testdata[i].expected_result, "[pcre] cli_pcre_scanbuff() failed for %s (%d != %d)", pcre_testdata[i].virname, ret, pcre_testdata[i].expected_result);

        // we cannot check if the virname matches because we didn't load a whole logical signature, and virnames are stored in the lsig structure, now.

        ret = cli_scan_buff((const unsigned char *)pcre_testdata[i].data, strlen(pcre_testdata[i].data), 0, &ctx, 0, NULL);

        // cli_scan_buff() doesn't check the number of alerts. When using CL_SCAN_GENERAL_ALLMATCHES
        // or if using `CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE` and `cli_append_potentially_unwanted()`
        // we need to count the number of alerts manually to determine the verdict.
        if (0 < evidence_num_alerts(ctx.this_layer_evidence)) {
            verdict = CL_VIRUS;
        }

        ck_assert_msg(verdict == pcre_testdata[i].expected_result, "[pcre] cli_scan_buff() failed for %s", pcre_testdata[i].virname);
        /* num_virus field add to test case struct */
        if (evidence_num_alerts(ctx.this_layer_evidence) > 0) {
            // Reset evidence for the next scan.
            evidence_free(ctx.recursion_stack[ctx.recursion_level].evidence);
            ctx.recursion_stack[ctx.recursion_level].evidence = NULL;
            ctx.this_layer_evidence                           = NULL;
        }
    }

    cli_ac_freedata(&mdata);
}
END_TEST

Suite *test_matchers_suite(void)
{
    Suite *s = suite_create("matchers");
    TCase *tc_matchers;
    tc_matchers = tcase_create("matchers");
    suite_add_tcase(s, tc_matchers);
    tcase_add_checked_fixture(tc_matchers, setup, teardown);
    tcase_add_test(tc_matchers, test_ac_logical_pattern_does_not_keep_borrowed_virname);
    tcase_add_test(tc_matchers, test_ac_compact_lsig_state);
    tcase_add_test(tc_matchers, test_ac_compact_scan_equivalence);
    tcase_add_test(tc_matchers, test_ac_compact_allocation_boundaries);
    tcase_add_test(tc_matchers, test_ac_scanbuff);
    tcase_add_test(tc_matchers, test_ac_repeated_prefix_does_not_shift_to_repeated_window);
    tcase_add_test(tc_matchers, test_ac_scanbuff_ex);
    tcase_add_test(tc_matchers, test_bm_scanbuff);
    tcase_add_test(tc_matchers, test_pcre_scanbuff);
    tcase_add_test(tc_matchers, test_ac_scanbuff_allscan);
    tcase_add_test(tc_matchers, test_ac_scanbuff_allscan_ex);
    tcase_add_test(tc_matchers, test_bm_scanbuff_allscan);
    tcase_add_loop_test(tc_matchers, test_matcher_nonterminal_indicators, 0, 30);
    tcase_add_test(tc_matchers, test_ac_weak_hit_preserves_lsig_accounting);
    tcase_add_test(tc_matchers, test_pcre_scanbuff_allscan);
    return s;
}
