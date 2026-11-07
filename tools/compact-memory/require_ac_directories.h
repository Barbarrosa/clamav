/* SPDX-License-Identifier: GPL-2.0-only
 * Internal exporters require the original complete construction indexes.
 * Do not silently export incomplete data from a production-sized engine.
 */
#ifndef CLAMAV_RESEARCH_REQUIRE_AC_DIRECTORIES_H
#define CLAMAV_RESEARCH_REQUIRE_AC_DIRECTORIES_H

static int cm_require_ac_directories(const struct cl_engine *engine)
{
    unsigned int target;
    for (target = 0; target < CLI_MTARGETS; target++) {
        const struct cli_matcher *root = engine->root[target];
        if (root && ((root->ac_patterns && !root->ac_pattable) ||
                     (root->ac_lists && !root->ac_listtable))) {
            fprintf(stderr, "Internal AC census/export requires an engine built "
                            "with -DENABLE_AC_DIRECTORY_RETENTION=ON.\n");
            return 0;
        }
    }
    return 1;
}

#endif
