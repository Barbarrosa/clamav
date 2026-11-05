# Five tests, in plain language

**The best next lead is still shared signature pieces.** The other tests were
useful mainly because they showed where a simpler method already does the job,
or where a promising saving disappears after the data is used.

I wrote [40 different ideas](memory-search-ideas.md), selected the five before
this pass's measurements, and tested all five. These are small, exact storage
experiments. They use public test fixtures and constructed examples, not the
official compiled full or restricted PDF/JPEG/PNG databases. No scanner code or rule
selection changed.

## What happened

All sizes below include each experiment's own storage headers and indexes. They
are **stored component bytes, not ClamAV's total RAM**. Different rows contain
different data and cannot be added into a whole-engine saving.

| Idea | Result on public test data | Did the search beat a simpler method? | Decision |
|---|---|---|---|
| 1. Choose shared signature pieces together | 756 → **689 bytes** | Yes: the greedy chooser stayed at 756 | Best candidate for testing on real compiled exports |
| 2. Choose compressed name blocks | 934 → **707 bytes before use**, then **1,485** after every name is unpacked and retained | No: ordinary fixed-size blocks also reached 707 | A cold-storage option, not a demonstrated lasting RAM saving |
| 3. Choose dense or shared matcher-table blocks | 603,018 → **58,890 bytes** in the simple byte-matcher model | No: ordinary shared blocks reached the same size | Keep simple sharing as the baseline; a new counting algorithm is not justified here yet |
| 4. Share exact endings of match lists | **504 → 504 bytes** | No | Measure real internal lists before spending more effort |
| 5. Choose compact number-field blocks | Two public columns reached **39 and 52 bytes** | No: simple whole-column formats reached the same sizes | Use simple formats first; adaptive boundaries may help irregular data |

The large matcher-table reduction belongs to a basic literal-byte automaton
built from test signatures. It is not a reduction measured on ClamAV's actual
compiled matcher. The raw and compressed comparisons use the same table.
The 689-byte token result reproduces the earlier best result. This pass adds
reading-work limits, a different candidate filter and the generic-only subset;
it does not count the same saving as an additional reduction.

## Where more careful choices helped

The constructed examples deliberately exercise interactions that public fixtures
may not contain. They demonstrate a mechanism, not its frequency in real data.

- **Signature pieces:** a previous constructed case saves nothing when pieces are
  chosen individually, but saves 10 bytes when two are chosen together. This pass
  also tests candidate generation and a limit on reading work. On the public
  sample, a tighter work allowance changes 689 bytes to **713 bytes**. Space and
  reading cost must be considered together.
- **Names:** carefully placed boundaries use **251 bytes**, versus **277** with
  fixed blocks, on a clustered-name example. Retaining unpacked names still costs
  extra memory; the smaller starting image does not remove that cost.
- **Matcher tables:** a mixed example uses **2,151 bytes**, versus **2,183** if
  every row uses shared blocks. Some rows should stay dense. With entirely
  distinct blocks, sharing expands the image; the optimizer correctly stays raw.
- **Match-list endings:** a deliberately shared-tail example uses **380 bytes**
  instead of **920** raw. But the simple greedy sharing method also gets 380.
  A tight two-link traversal limit raises the result to **704 bytes**.
- **Number fields:** adapting boundaries to changing runs uses **88 bytes**,
  versus **122** for the best tested fixed-block layout. Random-looking values
  correctly keep the **160-byte raw layout** rather than expanding it.

Trying a different signature-fragment filter did not improve the best answer:
its public result was 698 bytes instead of 689. That is useful negative evidence.
The small public generic-only signature subset also showed **no saving**.

## What this says about the linked algorithm

The [linked work](https://github.com/openai/math/blob/main/lean/docs/378.md) is a
mathematical counting construction. It is not supplied as a practical executable
that accepts our files. Inspection found
[noncomputable entry definitions](https://github.com/openai/math/blob/main/lean/OAI/Algorithms/SubexponentialSAT/SqrtLogSpace/NativeEntry.lean)
and a [finite precomputed fallback construction](https://github.com/openai/math/blob/main/lean/OAI/Algorithms/SubexponentialSAT/SqrtLogSpace/FiniteFallback.lean).
Installing Lean alone would not provide a ready-to-run compressor or counting
command. This pass did not independently check the complete proof or implement
its practical extraction.

Instead, these tests build the questions that such a solver could answer:
**can the exact data fit within this many bytes, without exceeding a reading-work
limit?** Ordinary SAT/MaxSAT software supplies the current working baseline.
Each of the five models also has a small fixed-width formula whose optimal
budget is accepted and whose one-byte-smaller budget is rejected.

There is an important reason not to reach immediately for the new algorithm.
The name and number-block choices also have straightforward exact dynamic
programs. The restricted table and shared-tail models can be expressed as
weighted selection/closure problems. A general counting solver may be unnecessary
for those families. Joint fragment selection remains the strongest of these five
places to investigate difficult combinations.

No speed advantage of the linked algorithm has been tested or established.

## What was checked

The final serial run passed **58 tests**: 42 for the five experiments and 16 for
the existing token and fixed-width budget infrastructure.

The tests reconstruct every stored signature byte, name, transition, number and
ordered list record used in the experiments. They retain duplicate occurrences,
attributes and the tested `next_same` coordinates. They also check malformed
images, integer limits and reading-work bounds. Small problems are checked
against independent exhaustive or dynamic-programming answers.

The name prototype additionally retains immutable views while more names are
unpacked. That is a test of this prototype's lifetime behavior, not a proof of
ClamAV's C pointer or allocation-order compatibility. A review found and fixed a
malformed-name expansion issue before final validation.

The compact models record storage before use, after full use and with two
generations alive. These are component counts. Solver/construction peaks,
allocator overhead, surrounding engine state and real reload RAM remain
unmeasured. In particular, a decoded block or list's payload size is not the
Python decoder's actual temporary-memory peak.

The token decoder has native CPU measurements. Other timings are Python
prototype checks, not native scanner benchmarks. Extra references and unpacking
can take more CPU; this work establishes no overall performance parity.

## What I would do next

Use freshly generated **real compiled token exports** for both full and Legal
Redress profiles. Compare joint fragment selection with raw storage, existing
dictionary compression and small compressed blocks under matching reading-work
and memory budgets. Test normal and hostile lookup patterns. Keep every selected
rule and all pattern boundaries and references.

Do not integrate a more complicated solver merely because it produces a smaller
toy example. Promote an approach only after it saves actual engine RAM, including
fully used data and reload overlap, at an acceptable measured CPU cost.

## Reproduce or inspect

The [machine-readable results](solver-five-results/summary.json) link all five
result files, commands, test logs and source hashes. The tools live in
`tools/compact-memory/solver-five`. Run from the repository root:

```sh
python3 -m venv /tmp/clamav-search-venv
/tmp/clamav-search-venv/bin/pip install python-sat==1.9.dev17
cc -std=c11 -O3 -Wall -Wextra -Werror \
  tools/compact-memory/probe_joint_dictionary.c -o /tmp/probe-joint-dictionary
/tmp/clamav-search-venv/bin/python tools/compact-memory/solver-five/run_five.py \
  --output /tmp/clamav-five-results --native-probe /tmp/probe-joint-dictionary
```

Choose a new output directory. Everything is offline and separate from the
scanner. These public fixture results do not replace official-database or
production qualification.
