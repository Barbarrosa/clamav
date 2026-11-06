# Preparing memory searches without hiding their costs

The branch now has an offline framework for asking: **which storage choices can
save memory while respecting explicit correctness and complexity constraints?**
It prepares inputs for conventional solvers and a future implementation of the
linked counting algorithm. It does not install a new representation in ClamAV.

The framework distinguishes three kinds of evidence:

- **What must be preserved:** all selected signatures, exact field values, duplicate
  identity, reporting requirements, pointer lifetimes, severity, parser/trust
  behavior, errors, limits and reload ownership.
- **What can be bounded:** reads, dependent calls, rank operations, decoding
  mechanisms, new formats, indexes, caches and known live storage.
- **What must be measured:** complete scanner CPU/latency, loading, updates,
  reloads, cold/hydrated RAM, scratch memory and concurrency on the same baseline
  hardware and workload.

An unknown measurement remains unknown. It cannot become a free operation,
zero-byte allocation or passed requirement.

## Which choices are represented

The catalog has 26 choices across eight families. They cover ordinary versus
byte-specialized/shared tokens, direct versus derived fields, logical-rule
sharing, matcher routing, names, zero-default scan state, allocation/reload
sharing and identity lookup. Promising experiments and their blockers are linked
beside each choice. Failed implementations remain distinct from new designs
that might overcome their problems.

The executable adapter currently searches **actual captured field programs**.
Their serializers, costs and exact reconstruction checks already exist. Other
families are explicit extension points, with their retained alternatives fixed
until a corresponding cost, implementation and verification adapter is supplied.
The tool does not add savings from unrelated experiments together.

The default run keeps the captured native representation. It also blocks the
current compact provider's extra binary search, because changing constant-time
field access into logarithmic-time lookup violates the default growth rule.
An explicitly relaxed research run can examine that tradeoff under additional
limits. A separate flag is needed to explore a category with a known component
slowdown. Neither flag can waive a declared correctness failure.

A measured failure can be fed back as an exclusion of one complete configuration.
That exclusion is bound to the captured data and choice definitions; it does not
silently reject every alternative in the same family.

## Complexity is part of the search

The field model charges descriptor visits, payload and identity reads, dependency
edges, popcounts, bounded rank loops and data tests. Dependencies are bounded and
cycles excluded. Separate caps limit active operations, new indexes, new formats,
compiled decoder cases and prototype reader code lines. Field reads add no query
allocations or persistent decoded cache.

Those are declared resource bounds, not CPU instructions. The tool also measures
source lines and branch/loop/allocation-call sites against matching upstream
files. These help assess maintenance cost; they are not an execution-time proof.
The current generic C reader contains seven decoder cases even when a selected
image uses fewer operations, and that distinction is recorded.

## Counts now have a defined meaning

The earlier model could assign different bookkeeping values to the same storage
choice. The new encoder makes every helper a deterministic consequence of the
actual choices. Inactive fields are fixed, and arithmetic and resource predicates
have unique answers. Ordinary Boolean counts therefore count **declared choice
configurations**, without extra copies introduced by helper variables.

Small synthetic queries have independently checked counts of 0, 2, 3 and 4 at
successive budgets. Conditional queries demonstrate choosing among alternatives.
This is a test of the encoding, not a memory result for real signatures or a
formal proof of every part of the framework.

The full query's documented canonical encoding is about **353 GiB packed**,
despite its much smaller DIMACS form. A compact input view now provides its bits
without creating that file: the measured process peaked at about **394 MiB RAM**.
It preserves the declared variable universe and linked unary-number/list framing.
This measures input handling, not the counting algorithm's working memory.

The [feasibility investigation](linked-counter-feasibility.md) identifies a more
decisive obstacle: the published parameter settings send our queries to a
fallback. The threshold for its proved large-input branch is astronomically
beyond a feasible explicit input. The new method itself has not run; a practical
adaptation would require additional algorithm development.

## What a promising result still needs

The runner rebuilds a chosen representation and verifies its captured values and
actual image/index byte costs. It reports conversion and equal-size reload
overlap, including the configured worker's known logical tracking arrays.
Uncaptured allocations and builder scratch remain outside the known subtotal.

Before a proposal could be promoted, complete-engine measurements must be bound
to the exact binaries, source configuration, database, files, hardware and
correctness contract. The evidence checker requires cold/warm and adversarial
cases and 18 performance/memory dimensions. It rejects missing data, semantic
changes and observed regressions. A favorable average cannot hide a slower pair.
A pass remains empirical; it does not prove performance on untested inputs.

The original upstream performance baseline and the branch's captured structural
control remain separate identities. Preserving the latter does not certify
equivalence to the former. The linked counting algorithm itself has not run.

[Run the tools and inspect the contracts](../tools/compact-memory/search-groundwork/README.md).
[Inspect the actual results and remaining gaps](search-groundwork-results/README.md).
