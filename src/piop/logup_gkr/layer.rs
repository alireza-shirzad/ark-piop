//! Fraction-tree layers of the LogUp-GKR prover, the eq tables its
//! sumchecks use, and the helpers that decide where work runs in parallel.

use ark_ff::PrimeField;
use ark_std::cfg_into_iter;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::{FractionInstance, Numerator};

/// Below this many elements a loop runs serially: handing it to the thread
/// pool costs more than the work.
pub(super) const SERIAL_BELOW: usize = 1 << 12;

/// Smallest piece a parallel indexed loop is split into.
#[cfg(feature = "parallel")]
const MIN_SPLIT: usize = 1 << 10;

/// Maps `f` over `jobs` in order, on the thread pool if `parallel` is set
/// (and the feature is on). The caller builds ONE flat list per step and
/// decides `parallel` from its total work, so parallel loops never nest.
pub(super) fn map_jobs<T: Send, R: Send>(
    jobs: Vec<T>,
    parallel: bool,
    f: impl Fn(T) -> R + Sync + Send,
) -> Vec<R> {
    #[cfg(feature = "parallel")]
    if parallel {
        return jobs.into_par_iter().map(f).collect();
    }
    #[cfg(not(feature = "parallel"))]
    let _ = parallel;
    jobs.into_iter().map(f).collect()
}

/// `(0..len).map(f)` unzipped straight into its two vectors, so a large layer
/// is written once and never zero-filled first.
fn unzip_indexed<R: Send>(
    len: usize,
    parallel: bool,
    f: impl Fn(usize) -> (R, R) + Sync + Send,
) -> (Vec<R>, Vec<R>) {
    #[cfg(feature = "parallel")]
    if parallel {
        return (0..len)
            .into_par_iter()
            .with_min_len(MIN_SPLIT)
            .map(f)
            .unzip();
    }
    #[cfg(not(feature = "parallel"))]
    let _ = parallel;
    (0..len).map(f).unzip()
}

/// One layer of a fraction tree, numerators in `p` and denominators in `q`.
/// The two children of fraction `j` of the layer above are entries `2j` and
/// `2j + 1`; the layer is kept in that interleaved order all the way through
/// its sumcheck.
#[derive(Default)]
pub(super) struct Layer<F> {
    /// Empty when every numerator is one (the input layer of a
    /// unit-numerator instance).
    pub(super) p: Vec<F>,
    pub(super) q: Vec<F>,
}

impl<F: PrimeField> Layer<F> {
    /// The layer above: adjacent fractions added.
    fn parent(&self, parallel: bool) -> Self {
        let (p, q) = (&self.p, &self.q);
        let len = q.len() / 2;
        let (p, q) = if p.is_empty() {
            // 1/a + 1/b = (a + b)/(a·b): one multiplication instead of three.
            unzip_indexed(len, parallel, |j| {
                let (a, b) = (q[2 * j], q[2 * j + 1]);
                (a + b, a * b)
            })
        } else {
            unzip_indexed(len, parallel, |j| {
                let (a, b) = (q[2 * j], q[2 * j + 1]);
                (p[2 * j] * b + p[2 * j + 1] * a, a * b)
            })
        };
        Self { p, q }
    }
}

/// All layers of one instance.
pub(super) struct LayerStack<F> {
    /// `(P, Q)` of the root fraction.
    pub(super) root: [F; 2],
    /// Layers `n, n-1, .., 1`, so that `pop` yields them in the order the
    /// protocol consumes them.
    pub(super) layers: Vec<Layer<F>>,
}

impl<F: PrimeField> LayerStack<F> {
    fn new(instance: FractionInstance<F>, parallel: bool) -> Self {
        let p = match instance.num {
            Numerator::One => Vec::new(),
            Numerator::Values(values) => values,
        };
        let mut layer = Layer { p, q: instance.den };
        let mut layers = Vec::with_capacity(layer.q.len().ilog2() as usize);
        while layer.q.len() > 1 {
            let parent = layer.parent(parallel && layer.q.len() >= SERIAL_BELOW);
            layers.push(layer);
            layer = parent;
        }
        // Only a zero-variable unit-numerator instance gets here without
        // numerators.
        let numerator = layer.p.first().copied().unwrap_or_else(F::one);
        Self {
            root: [numerator, layer.q[0]],
            layers,
        }
    }
}

/// Builds the layers of every instance, bottom-up. The denominators must be
/// non-empty.
///
/// Large instances are folded one after another with parallel loops; the
/// small ones are spread over the pool, each folded serially. That uses the
/// pool both within large instances and across many small ones without
/// nesting one parallel loop in another.
pub(super) fn build_layer_stacks<F: PrimeField>(
    instances: Vec<FractionInstance<F>>,
) -> Vec<LayerStack<F>> {
    let mut stacks = Vec::with_capacity(instances.len());
    let mut small = Vec::new();
    let mut small_total = 0;
    for (i, instance) in instances.into_iter().enumerate() {
        if instance.den.len() < SERIAL_BELOW {
            small_total += instance.den.len();
            small.push((i, instance));
        } else {
            stacks.push((i, LayerStack::new(instance, true)));
        }
    }
    stacks.extend(map_jobs(
        small,
        small_total >= SERIAL_BELOW,
        |(i, instance)| (i, LayerStack::new(instance, false)),
    ));
    stacks.sort_unstable_by_key(|(i, _)| *i);
    stacks.into_iter().map(|(_, stack)| stack).collect()
}

/// `eq(point, x)` for all `x` in `{0,1}^k`, with `point[j]` matched to bit
/// `j` of the index. The empty point gives the one-entry table `[1]`.
pub(super) fn eq_table<F: PrimeField>(point: &[F]) -> Vec<F> {
    if (1usize << point.len()) < SERIAL_BELOW {
        return eq_table_serial(point);
    }
    // Outer product of the tables of the two halves of the point: the same
    // number of multiplications as doubling all the way, in one parallel
    // pass that writes the table once and never zero-fills it first.
    let split = point.len() / 2;
    let lo = eq_table_serial(&point[..split]);
    let hi = eq_table_serial(&point[split..]);
    let mask = lo.len() - 1;
    cfg_into_iter!(0..1usize << point.len(), MIN_SPLIT)
        .map(|x| lo[x & mask] * hi[x >> split])
        .collect()
}

fn eq_table_serial<F: PrimeField>(point: &[F]) -> Vec<F> {
    let mut table = Vec::with_capacity(1 << point.len());
    table.push(F::one());
    for r in point {
        // The new variable is the top bit: the upper half is the old table
        // times r, the lower half what is left of it.
        for x in 0..table.len() {
            let hi = table[x] * r;
            table[x] -= hi;
            table.push(hi);
        }
    }
    table
}
