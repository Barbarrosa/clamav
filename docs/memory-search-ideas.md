# Forty ways to search for smaller ClamAV data

These ideas use the linked algorithm in the same basic way: **ask whether an exact
arrangement fits a memory budget and a limit on the work needed to read it**.
If the answer is yes, try a smaller budget. Recover and independently check the
chosen arrangement before trusting it. This can guide an offline compiler; it
does not require the scanner to run a solver on uploaded files.

The [linked research](https://github.com/openai/math/blob/main/lean/docs/378.md)
gives a mathematical counting construction, not a ready-to-run solver. The five
tests below use ordinary SAT/MaxSAT software to test the memory problems and
their encodings. They do not test the new algorithm's practical speed.

## The five selected before these tests

Selection favors a potentially substantial stored component, an exact check we
can actually run, existing decoder ideas, and a contained offline experiment.
It does not predict a savings percentage. We prioritized these five over arena
scheduling or backing-file placement because the latter need real allocation,
storage and deployment traces that this checkout does not contain.

| Priority | Idea number | Test | Why selected | Important risk |
|---|---:|---|---|---|
| 1 | 1 | Choose shared signature pieces together | Existing input format and independent decoder; clear interacting choices | Candidate selection can miss good combinations |
| 2 | 6 | Choose name blocks and restart points | Names are large; exact reconstruction is straightforward | Unpacked names must remain alive for callers |
| 3 | 24 | Choose dense or shared matcher-table blocks | Every table entry can be checked | An extra lookup can cost CPU |
| 4 | 21 | Share identical tails of ordered match lists | Sharing can avoid a decompressor | Order, duplicate occurrences and attributes must survive |
| 5 | 16 | Choose number-field block boundaries and formats | Several existing simple formats; exact integer checks | Headers and lookup work can erase the saving |

The ranking is an engineering judgment made before this pass's measurements,
not a numerical forecast or a claim these are globally the best five ideas.
See [the results in plain language](memory-search-five-results.md).

## The forty distinct choices

1. **Shared signature pieces — selected.** Choose which repeated pieces to store
   once and how each signature uses them, paying for all references.
2. **Separate signature dictionaries.** Decide which signatures share a dictionary
   and which need their own; smaller references must outweigh duplicated pieces.
3. **Pieces built from other pieces.** Choose a small exact grammar, with a strict
   limit on how many nested expansions a lookup can require.
4. **Signature compression blocks.** Choose where blocks start and whether each
   uses raw bytes or an existing compressor, including scratch-memory costs.
5. **Byte or wider signature storage.** Choose where byte-only storage is valid
   and where tagged wider values need an exact fallback.
6. **Name blocks and restarts — selected.** Choose where a name starts from scratch
   instead of rebuilding a prefix from earlier names; bound the rebuild work.
7. **Shared name substrings.** Choose repeated pieces within different names,
   rather than sharing only entirely identical names.
8. **Names ready for direct access.** Choose which name blocks start unpacked and
   which expand later, while charging for all names after they have been used.
9. **Stable name-file chunks.** Choose immutable mapped chunks while counting
   their real file-cache cost; returned addresses must remain valid.
10. **One name arena across matcher types.** Share identical names used by
    different matcher families without reducing their required lifetime.
11. **Logical descriptors after ordering.** Choose which identical descriptors to
    share after match order is fixed, avoiding earlier allocation-order failures.
12. **Shared expression parts.** Factor repeated logical subexpressions while
    retaining the same evaluation, alerts and error behavior.
13. **Shared auxiliary arrays.** Choose which identical range, macro or scalar
    arrays can share storage while preserving exact pointer coordinates.
14. **Exceptional length bounds.** Decide which pattern bounds belong in existing
    extension records, including the cost of enlarged extensions and relocation.
15. **Proven redundant fields.** Remove a stored value only where source rules
    prove it can be recovered; charge an exact escape for other cases.
16. **Number blocks and formats — selected.** Choose block boundaries together
    with raw, constant, regular-step or packed-difference storage.
17. **Related number fields together.** Choose which columns share a descriptor
    or exact correlated encoding; count group headers and exceptions.
18. **Local reference bases.** Group records so references can be small offsets,
    with exact wider escapes where needed.
19. **Exception storage.** Choose a plain list, sparse positions or bitmap for
    exceptional values, including the cost of locating an exception.
20. **Increasing offset directories.** Choose raw offsets, difference blocks or
    a compact searchable layout, paying for the search support.
21. **Ordered list tails — selected.** Share exactly identical endings of match
    lists, including order, occurrence identity, duplicate counts and attributes.
22. **Small lists kept inline.** Decide which candidate lists belong directly in
    their owner and which justify a shared external allocation.
23. **Failure-output duplication.** Decide when to copy an ordered output list
    and when to follow a bounded chain to it.
24. **Matcher-table microblocks — selected.** Choose which rows remain dense
    and which refer to shared blocks of destinations.
25. **Equivalent input bytes.** Group byte values only where all relevant matcher
    destinations agree, preserving exact behavior for every byte.
26. **Default-transition links.** Choose exact default chains or valid cycles
    while limiting the number of dependent lookups.
27. **Dense acceleration regions.** Spend a fixed memory allowance keeping some
    frequently used transition regions dense; all other paths remain exact.
28. **Packed hash buckets.** Group size-specific buckets into slabs and choose
    local offset bases without changing lookup or duplicate selection.
29. **Exact digest prefix sharing.** Choose prefix partitions that save bytes
    while retaining every remaining digest bit and exact membership checking.
30. **Static bucket placement.** Choose directory capacity and placement to bound
    probes without discarding keys or changing equality behavior.
31. **Old/new generation chunk sharing.** Choose immutable chunk boundaries to
    reuse identical data across a database reload, counting both generations.
32. **Bounded update overlays.** Choose a base plus exact changes while limiting
    the number of layers needed for a lookup.
33. **Compilation order.** Schedule independent construction stages so fewer
    temporary objects are alive at the same time.
34. **Arenas grouped by lifetime.** Place objects in pools that can actually be
    released together; theoretical freed bytes are insufficient.
35. **Allocation size classes.** Choose classes for measured object sizes to
    reduce rounding while preserving alignment and required addresses.
36. **Scratch-buffer reuse.** Share storage between buffers whose lifetimes
    cannot overlap, preserving supported concurrency.
37. **Logical scan-state storage.** Choose dense, zero-default or exact sparse
    layouts while accounting for the case where every entry is touched.
38. **Complete evidence-history storage.** Choose literal or run blocks without
    deleting any push/pop history, name pointer, severity or object context.
39. **Clean-result cache partitioning.** Choose capacities and partitions under
    a measured CPU/memory budget without weakening cache validity rules.
40. **A compatible whole-engine portfolio.** Choose among component layouts
    together, charging shared scratch, construction and reload overlap instead
    of adding separate experiments' best savings.

These are different decisions even where the same solver machinery applies.
Ideas 1 and 2, for example, choose dictionary contents versus which records share
a dictionary; ideas 21 and 23 choose identical stored tails versus traversal of
existing failure outputs. None permits omitting a required rule, approximate
digest membership, reordered reports or invalidating an escaped name pointer.

## What the counting result contributes

Each bounded problem can be encoded as a Boolean feasibility question with a
byte budget. A positive count means at least one arrangement exists. It does
not automatically give a practical search speedup or a count of distinct physical
layouts: encoder variables and equivalent descriptions can multiply assignments.
Recovering a solution and checking it costs work too.

The five tests include clauses of width at most three, making this connection
concrete. Encoding overhead and all extra variables must be charged before
applying an asymptotic solver bound. Conventional solvers and small independent
oracles provide the current executable baseline.
