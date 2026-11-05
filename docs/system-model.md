# The real-engine model, in plain language

**The solver found a way to represent the captured engine data in about
453 MiB instead of 624 MiB: a 27.45% reduction.** Every captured field value
can be recovered exactly. These are counted storage bytes in a model, not a
measured reduction in ClamAV's running RAM.

I built this branch's real ClamAV library, loaded a signed official database
snapshot containing **3,628,192 signatures**, and captured its compiled matcher
and logical-rule structures. This replaces the earlier small examples with
actual engine data. It covers the full profile; the PDF/JPEG/PNG with PE exclusions profile was
not measured in this pass.

The question given to the solver was: *How should each field be stored, or
calculated from another field, so that all answers stay exactly the same and
each answer takes only a limited amount of work?*

For example, two pattern-length fields usually contain the same number. The
solver chose to store one field and just **110 exceptions** for the other,
across 1.5 million patterns. It also found fields that were constant, fields
that could use fewer bits, and pointers that could be stored as offsets. It
chose these relationships together while avoiding circular dependencies.
It could keep the original representation wherever that was better.

| Allowance for reading one field | Known modeled storage | Reduction |
|---|---:|---:|
| Original structures | 624.06 MiB | — |
| Very small: 1 work unit | 602.95 MiB | 3.38% |
| 2 work units | 531.96 MiB | 14.76% |
| 3 work units | 516.50 MiB | 17.24% |
| 16 work units | **452.73 MiB** | **27.45%** |

A work unit is part of the model's accounting, not a processor instruction or
a timing guarantee. Looking up an object's identity costs extra; the model
includes the storage for those indexes and reports their reading cost
separately.

The result includes **295.07 MiB left unchanged**, such as signature bodies,
names, original directories and hash data. That unchanged part already exceeds
the earlier 202.042 MiB goal. Reaching that goal would require a broader design
that also changes some of this data. This experiment does not prove such a
design impossible.

The smaller representation has a cost. In a separate C-reader experiment,
pattern-field reads used about **1.69 times as much CPU** for the smallest
layout. Logical-rule field reads used about 0.71 times as much. These were
short, artificial access traces after full verification, with object lookup
excluded. They do not establish whole-scanner performance.

The checks reconstructed all **75,460,242 field values** in each of the four
profiles. A separate check compared the native pointer relationships and
another independently checked the scalar export. The actual solver assignment
was then replayed back into the captured values, rather than trusting its
reported size. Duplicate records, original identities and ordered links stay
distinct. Scanner behavior and callback ordering have not been tested with a
replacement engine.

I also expressed the complete best model as a fixed-width Boolean problem:
about **288,000 variables and 982,000 clauses**, with at most three entries per
clause. This is an input in the linked algorithm's domain. Ordinary RC2 MaxSAT
found the layout; ordinary Minisat verified its extended Boolean answer.
Minisat's two attempts to find answers without that starting answer each timed
out after 30 seconds, including the one-byte-smaller budget. Those timeouts
prove neither feasibility nor impossibility.

**The algorithm in your link was not executed.** Its published Lean construction
does not supply a ready executable solver, and this work has not extracted one.
The actual formulas, solver answers, tests and results are now available for
inspection and for trying another solver. No speed advantage of the linked
algorithm has been demonstrated.

Memory during construction still matters. The smallest layout's counted
in-place conversion peak is about **782 MiB**. Keeping a converted old generation
while converting an equal-sized replacement reaches about **1,234 MiB**, before
scan workspaces, compiler/solver scratch space and unknown allocations. The
format does not retain a decoded-field cache, but these counts do not establish
cold-cache or hydrated-cache process RAM.

The useful finding is that **relationships between actual fields offer
substantial savings worth investigating**, with an observed reading-cost
tradeoff. The optimum applies only to the generated candidate programs. More
general programs, other database snapshots and actual page reclamation remain
outside this result.

[Results, solver files and reproduction instructions](system-model-results/README.md).
