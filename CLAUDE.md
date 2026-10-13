# ark-piop

## Build and tests
- `just ci` runs the format check, clippy and the tests, the last two with
  `test-utils` and again with `test-utils,honest-prover`. CI formats with
  nightly: `cargo +nightly fmt --check`.
- truth-table builds against this checkout through a path patch. Check it
  after changing anything `pub` here.
- The prover and the verifier must consume tracker ids and the transcript in
  the same order. A change to one side needs the same change on the other.

## Comments and docs
- A comment says what the code cannot: why it is this way, an invariant, a
  soundness condition, a constraint that lives elsewhere. If deleting it
  loses the reader nothing, delete it.
- Do not restate the name, the signature or the next line (`/// Returns the
  id.` on `fn id()`, `// Track the commitment` above `track_commitment(..)`).
  A `pub` item needs a doc only when the doc adds to its name.
- One to three lines by default. A longer block is for an algorithm, a
  protocol or a data layout: the statement, the steps, what soundness needs.
  Say each thing once; an item's doc does not repeat its module's doc, and a
  module doc does not list what its items already say.
- No history. What the code used to do, the bug that led to it, how it was
  found, commit hashes, PR numbers, dates, measurements from one run and
  words like "now", "no longer", "previously" belong in the commit message.
  State the present rule and its reason.
- No status notes ("currently wired", "step 4d is done"), no references to
  context the reader does not have ("the fix above", "as discussed"), no
  section banners, no commented-out code.
- The paper is context the reader has: cite it by section or protocol number
  instead of re-deriving it.

## Helper functions
Extract a function only when one of these holds:
1. it is a meaningful logical block used in more than one place;
2. it is used once, but it is a meaningful logical block and naming it makes
   the caller easier to read.

Otherwise keep the code inline. In particular, do not add a function that
only forwards to another one, that wraps one expression, that exists to
shorten its caller without being a step a reader would name, or that takes
most of its caller's locals as parameters.
