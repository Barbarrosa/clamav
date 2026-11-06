# Finding memory overhead by adding controlled padding

**Yes: adding small, known amounts of memory is useful for finding where to
investigate next.** The experiment points first to names, candidate lists and
pattern records. It also exposes allocator rounding and memory retained after
temporary objects are freed.

The padding experiment measures how strongly an area responds to extra bytes.
It does **not** establish that the original bytes are unnecessary, or that the
measured increase could be recovered as a saving.

## What was tested

An opt-in build adds **8 or 32 bytes to each allocation request** in one selected
area. It writes those bytes so they occupy real memory. Ordinary builds keep
this option disabled. There is no change to the default scanner or its rules.

The first screen covered **12 groups** using the full signed database with
**3,628,192 signatures**. It ran 28 fresh processes: two padding amounts for each
group, three interleaved zero-padding controls and one ordinary-build control.
The control is this branch's retained engine, rather than upstream ClamAV.

The three largest responses were repeated twice with separate controls.
Temporary matcher nodes were repeated too, because their memory remained
interesting after compilation. Those 16 additional runs reproduced the findings.
Every process had a 4 GiB address-space limit, a 120-second CPU soft limit and a
150-second wall limit. The cumulative padding limit was 512 MiB.

The screen and repeats scanned nine fixed benign, positive and malformed files.
The follow-up reload experiment uses the complete 163-file fixture corpus and
retains two full engines simultaneously. It scans the primary engine, then
compiles a replacement and measures overlap and freeing; it does not scan the
replacement. The harness records return codes,
verdicts, final names, ordered captured callbacks and input hashes. This checks
the observed cases; it is not an all-input correctness or performance proof.

Across the screen, repeats and reload experiment, **all 51 processes completed
and all 1,537 primary-engine scan transcripts matched their controls**. No dose
was cut short by the padding cap. An independent audit rechecked the fixture
identities, artifact hashes, counters and summary arithmetic.

## Which areas responded most

These are increases in **compiled resident RAM**, relative to the median of
three zero-padding screen controls. The zero controls were about 791 MiB and
varied by only 0.07 MiB. Each nonzero screen cell is one observation.

| Allocation group | Add 8 bytes per request | Add 32 bytes per request |
|---|---:|---:|
| Signature names | +28.1 MiB | +144.4 MiB |
| Candidate lists and their directories | +18.1 MiB | +88.7 MiB |
| Pattern records, extensions and directories | +14.2 MiB | +60.1 MiB |
| Signature tokens and special-pattern metadata | +13.4 MiB | +53.0 MiB |
| Logical-rule records, expressions and directories | +7.4 MiB | +47.6 MiB |
| Hash matcher allocations | +6.8 MiB | +22.7 MiB |
| Matcher nodes, including temporary builder nodes | +4.3 MiB | +21.5 MiB |
| Other pool requests | about zero | +2.1 MiB |
| Other annotated heap requests | +0.1 MiB | +0.2 MiB |
| Build queues and node-index storage | about zero | +0.2 MiB |
| Transition rows and their directory | +0.1 MiB | +0.1 MiB |
| Annotated scan-state arrays and match records | +0.1 MiB | +0.1 MiB |

The extra paired runs found median 32-byte responses of **144.2 MiB for names,
88.7 MiB for candidates, 60.2 MiB for patterns and 21.3 MiB for nodes**. Small
responses should not be ranked confidently from these few observations. Scan
state also depends strongly on the scanned files and concurrency.

These numbers suggest investigating shared name storage, fewer small candidate
allocations and tighter pattern bookkeeping. They do not give savings targets
of 144, 89 or 60 MiB: the experiment deliberately created that extra memory.

Keeping two engines alive made the 32-byte padding cost larger:

| Group | Extra resident RAM at compiled reload overlap |
|---|---:|
| Names | +290.7 MiB |
| Candidates | +176.3 MiB |
| Patterns | +101.3 MiB |

These are single paired reload observations after scanning the full fixture
corpus, not a universal doubling rule or peak-memory guarantee. Freed chunks,
page residency and allocator reuse affect the result.

## A small response can hide existing overhead

The transition-table result is the clearest example. A row contains **1,024 bytes
of data**, but the pool puts it in a **1,176-byte fragment**. Adding 8 or 32 bytes
still fits that fragment, so the padding trial barely moves resident memory.

An independent check ran the actual pool allocator over 144 combinations of
request size and starting alignment. It confirmed the size-class calculation.
Using the earlier full-engine capture's 76,968 retained rows, their fragments
occupy about **11.2 MiB above the row data**. This includes headers and alignment
as well as rounding; some overhead is required.

A hypothetical 1,040-byte fragment class would reduce the modeled charge by
about **10.0 MiB** for those rows. A similar logical-record example gives about
**3.6 MiB**. Neither allocator change was implemented, and these are not measured
RSS savings. Changing classes also changes reuse, addresses and potentially
reporting order, so it needs a separate experiment.

## Temporary memory can leave a lasting footprint

The retained flat-node layout copies matcher nodes into a compact array and
frees the old individual builder nodes. Padding the node group by 32 bytes still
left about **21 MiB more resident memory after compilation** in repeated runs.

The final arrays receive padding per allocation, rather than per node. This
therefore points toward pool reuse, fragmentation and the lifetime of builder
allocations as useful investigation targets. It does not prove that every extra
resident byte belongs to a freed node. A previous disposable-pool implementation
changed duplicate-alert ordering and remains disabled; this result does not
qualify it for use.

## What the measurements mean

The probe covers explicitly tagged engine structures, centralized pool requests
and common heap helpers. It does not intercept every direct heap allocation,
Rust allocation, bundled parser or external library. The group names describe
the annotated paths, rather than a complete census of every subsystem.
The current measurements and harness target Linux with 64-bit pointers.

Padding is per **request**, not per byte or per array element. A large array gets
one dose; millions of separately allocated names get millions of doses. A small
response from an array does not mean the array has little memory worth saving.

Allocation counters and added-byte totals accumulate over time. Reallocation can
reuse the same block, and freed fragments can remain in a pool. Consequently:

- Cumulative added bytes are not live padding and cannot be divided into the
  RSS increase to obtain an allocator amplification factor.
- Pool carved extent includes freed chunks and bookkeeping. It is not live
  payload; mapped extent is not necessarily resident memory.
- Memory left after freeing an engine is not automatically a leak: process
  caches, shared runtime state and heap retention also contribute.
- Injected padding intentionally changes allocation classes and CPU/cache costs.
  These timing observations cannot qualify a memory-saving implementation.

Read the [evidence and exact reproduction steps](allocation-perturbation-results/README.md)
or the [tool guide](../tools/compact-memory/allocation-perturbation/README.md).
