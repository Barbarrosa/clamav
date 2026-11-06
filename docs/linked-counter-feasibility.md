# Can the linked counting algorithm run practically?

**A compact view of the input fits in ordinary memory. The published counting construction is
not a practical way to solve our current searches.** Its settings send our
queries to a fallback, rather than the new method that gives the theoretical
speed improvement. A practical version of the underlying ideas would require
additional algorithm development.

This assessment follows the [document you linked](https://github.com/openai/math/blob/4eaee87548250b2682affda7d05d947c05554bae/lean/docs/378.md)
to the project's source and paper at revision
[`4eaee875`](https://github.com/openai/math/tree/4eaee87548250b2682affda7d05d947c05554bae).
The [machine-readable evidence](linked-counter-feasibility-results/README.md)
records source hashes, exact parameter calculations and bounded input tests.
The counting algorithm itself was **not executed**, and its Lean proof was not
independently rebuilt.

## What worked within a small budget

The real storage-choice query has **295,443 Boolean variables** and about a
million clauses. Its ordinary text file is about 20 MiB. The linked construction
uses a much more verbose encoding: about **353 GiB** even when packed into bits.

That does **not** mean we must load a 353 GiB file. I implemented a view that
calculates requested bits from the compact formula. Long repeated stretches can
be visited as a value and a length, without expanding them.

A test with a **2 GiB address-space limit and 120-second wall limit**:

| Input task | Measured result |
|---|---:|
| Read the formula and build its index | 6.16 seconds |
| Peak resident RAM, including formula parsing | 394.3 MiB |
| Additional index | 7.8 MiB |
| Read 100,000 randomly selected bits | 0.27 seconds |
| Visit the first 100,000 repeated-bit runs | 0.25 seconds |
| Separate complete run traversal, including input preparation | 39.71 seconds |

The complete traversal visited **12,727,852 runs** covering all 3.03 trillion
logical bits. Its total length and number of one bits matched separate sums
from the encoding grammar, and its peak RAM was about 394 MiB. Its checksum
covers the run records, not a materialized 353 GiB byte stream.

These measurements cover input access only. They do not include a counter's
working memory or count computation. Small independent tests compare the view's
bits against the original encoder. Source hashes and the precise resource limits
are saved with the results.

## Why the published method still does not run practically

The paper's improvement is an eventual guarantee: it applies once problems are
sufficiently large. Its explicit settings make “sufficiently large” far beyond
our query, or any feasible explicit input.

One setting must be at least two before the new method is used. For our query
it is **zero**. It is also zero for every variable count from five through
`2^64`. The Lean construction chooses a cutoff after which that setting is
always at least two. An exact arithmetic check shows that this cutoff exceeds
`2^639999` variables—a number with about 192,659 decimal digits.

Our small test queries also take the fallback. Making them smaller therefore
does not provide a demonstration of the new method. Padding them to reach the
proved large-input branch would itself require an impossible input size.

The fallback is different in the two descriptions:

- **The paper uses exhaustive search.** That can handle tiny examples, but
  enumerating all assignments for 295,443 variables is impractical.
- **The formal machine uses a fixed lookup construction for the finite range.**
  Expanding that construction literally would require an astronomical number
  of states, even with a cutoff of only 20. It is not a deployable lookup table.

A mathematical program can describe such a table as a function without storing
every entry. Consequently, its table size is **not a RAM lower bound for every
possible implementation**. An implementation would still need to calculate the
requested count. Using an ordinary counting solver for that calculation is a
useful fallback, but does not demonstrate the new method's speed advantage.

There is another cost to avoid in an eventual implementation. The literal formal
frontend copies and parses the verbose input bit by bit. One phase alone has
about **27 trillion structured steps** for our query. These are formal steps,
not measured CPU instructions. The compact view makes input access cheap; it
does not automatically justify skipping those steps or the counter's later work.

## What this establishes, and what remains possible

The input-access prototype avoids holding the expanded input in RAM. We identified a
separate, decisive obstacle in the published settings. We have **not** established
a practical runtime or memory budget for an implementation of the new method.
An asymptotic polynomial-space guarantee also leaves constants and exponents
that matter greatly in an actual program.

A redesigned implementation could use compact formulas, accelerate input
operations and choose different parameters. It would need independent checks
that its counting identities remain valid, actual size estimates for its
intermediate objects, and measurements against conventional counters. Merely
lowering the published cutoff would leave its proved conditions unsatisfied.

Conventional SAT/MaxSAT remains the executable route for the current memory
searches. Our exact queries and small known-count examples remain available for
testing a future implementation. This assessment concerns practical use of the
published construction; it does not refute its asymptotic theorem or prove that
all adaptations of its ideas must be impractical.

## Exact source checks

The audit tool verifies inspected source bytes against their pinned Git blobs.
It evaluates the following integer definitions:

```text
lambda = ceil(log2(n))
nu = ceil(log2(lambda))
s(n) = floor(sqrt(lambda)) // nu^2
```

For the full query, `lambda=19`, `nu=5`, and `s=0`. At `n=2^639999`,
`lambda=639999`, `nu=20`, and `s=1`. Therefore any threshold after which
`s(n)>=2` always holds must exceed that witness. The schedule is not monotone;
this is a lower bound on the eventual cutoff, not a claim about the first
isolated value where `s=2`.

Relevant pinned sources:

- [Parameter definitions](https://github.com/openai/math/blob/4eaee87548250b2682affda7d05d947c05554bae/lean/OAI/Algorithms/SubexponentialSAT/SqrtLogSpace/Asymptotics.lean#L14-L19)
  and [cutoff selection](https://github.com/openai/math/blob/4eaee87548250b2682affda7d05d947c05554bae/lean/OAI/Algorithms/SubexponentialSAT/SqrtLogSpace/NativeLargeEntry.lean#L48-L50).
- [Final machine composition](https://github.com/openai/math/blob/4eaee87548250b2682affda7d05d947c05554bae/lean/OAI/Algorithms/SubexponentialSAT/SqrtLogSpace/Final.lean)
  and [finite fallback](https://github.com/openai/math/blob/4eaee87548250b2682affda7d05d947c05554bae/lean/OAI/Algorithms/SubexponentialSAT/SqrtLogSpace/FiniteFallback.lean).
- [Frontend](https://github.com/openai/math/blob/4eaee87548250b2682affda7d05d947c05554bae/lean/OAI/Algorithms/SubexponentialSAT/SqrtLogSpace/NativeFrontend.lean):
  its stated ambient trace length simplifies to `9*L+2*n+12`.
- [Paper](https://github.com/openai/math/blob/4eaee87548250b2682affda7d05d947c05554bae/preprints/The-Exponential-Time-Hypothesis-is-False-October-25-2026/paper.pdf),
  Proposition 6.4, printed pages 43–44: the same schedule and exhaustive fallback.

For a cutoff `B`, the fallback ranges over all CNFs on at most `B` variables,
not just clauses of width three. The largest canonical encoding has length
`M=B+2+2^(2B)*(4B^2+6B+4)`. Its scanner's state domain has `2^(M+1)` members.
At `B=20`, `M=1,895,558,046,285,846`. These are literal construction sizes;
no such table or input was materialized.
