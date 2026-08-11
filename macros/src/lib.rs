//! Instrumentation attributes for ark-piop's prover pipeline.
//!
//! The prover reports two kinds of per-stage telemetry on the `bench_stats`
//! target: a span whose lifetime is the stage's duration, and a pair of
//! tracker snapshots bracketing it. Written by hand that is four lines of
//! bookkeeping wrapped around every stage, and the snapshot half is easy to
//! get subtly wrong — see [`piop_stage`] on the early-return trap.
//!
//! Both live in the attribute instead, so stage bodies contain only the
//! algorithm.

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Error, ItemFn, LitStr, Result, ReturnType, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

/// The tracing target every span and snapshot this macro emits is declared
/// on. Must stay in sync with `ark_piop::prover::tracker::
/// SNARK_PROVER_SPAN_TARGET`; a proc-macro crate can't reference a const
/// from the crate that depends on it, so this is the one duplicated string.
const BENCH_STATS_TARGET: &str = "bench_stats";

/// Parsed `#[piop_stage(...)]` arguments. Every field is optional, so the
/// attribute can carry a span, a snapshot pair, or any mix.
#[derive(Default)]
struct StageArgs {
    span: Option<LitStr>,
    snapshot_start: Option<LitStr>,
    snapshot_end: Option<LitStr>,
}

impl Parse for StageArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut args = StageArgs::default();
        while !input.is_empty() {
            let key: syn::Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            let value: LitStr = input.parse()?;
            let slot = match key.to_string().as_str() {
                "span" => &mut args.span,
                "snapshot_start" => &mut args.snapshot_start,
                "snapshot_end" => &mut args.snapshot_end,
                other => {
                    return Err(Error::new(
                        key.span(),
                        format!(
                            "unknown `piop_stage` argument `{other}`; \
                             expected `span`, `snapshot_start`, or `snapshot_end`"
                        ),
                    ));
                }
            };
            if slot.is_some() {
                return Err(Error::new(
                    key.span(),
                    format!("duplicate `{key}` argument"),
                ));
            }
            *slot = Some(value);
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }
        Ok(args)
    }
}

/// Build the `phase` argument for an `emit_tracker_snapshot` call.
///
/// A plain literal is passed straight through as a `&'static str`. One
/// containing `{` is treated as a format string, so a stage can name its
/// snapshot after one of its own parameters — `"bucket_{bucket_index}_start"`
/// resolves against the argument in scope via `format!`'s inline captures.
/// Only that case pays for an allocation.
fn snapshot_phase(literal: &LitStr) -> proc_macro2::TokenStream {
    if literal.value().contains('{') {
        quote! { &format!(#literal) }
    } else {
        quote! { #literal }
    }
}

/// Wrap a prover stage in its `bench_stats` span and tracker snapshots.
///
/// ```ignore
/// #[piop_stage(
///     span           = "compile_sc_subproof",
///     snapshot_start = "compile_start",
///     snapshot_end   = "after_compile_sc_subproof",
/// )]
/// fn compile_sc_subproof(&mut self) -> SnarkResult<Option<Subproof>> {
///     // just the algorithm
/// }
/// ```
///
/// Requires `self` to expose `emit_tracker_snapshot(&self, phase: &str)`
/// whenever a snapshot argument is given.
///
/// # Why the body moves into a closure
///
/// The end snapshot has to fire on *every* exit path. Stages return early —
/// `compile_sc_subproof` has two `return Ok(None)` paths for the claim-free
/// case, and any `?` is another exit. A hand-written snapshot above the
/// final `Ok(..)` silently skips all of them, which is exactly the bug this
/// attribute exists to make unwritable. Running the body as a closure turns
/// each of those into a return *from the closure*, so the snapshot always
/// runs and the value flows out unchanged.
///
/// # Why the span goes inside
///
/// A snapshot walks every materialized poly to sum heap bytes, which is not
/// free. The span is entered after the start snapshot and dropped before the
/// end one, so that cost never lands in the stage's reported duration.
#[proc_macro_attribute]
pub fn piop_stage(args: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as StageArgs);
    let mut function = parse_macro_input!(item as ItemFn);

    if args.span.is_none() && args.snapshot_start.is_none() && args.snapshot_end.is_none() {
        return Error::new_spanned(
            &function.sig.ident,
            "`piop_stage` needs at least one of `span`, `snapshot_start`, or `snapshot_end`",
        )
        .to_compile_error()
        .into();
    }

    let body = &function.block;
    let target = BENCH_STATS_TARGET;

    // Annotate the closure with the function's return type so `?` and
    // `return` inside the body keep resolving the way they did before.
    //
    // Deliberately not a `move` closure: the body needs `&mut self`, and a
    // move would hand ownership of the receiver to the closure, leaving
    // nothing for the end snapshot to call. A reborrow instead ends when the
    // closure is dropped at the end of the statement, which is exactly when
    // the snapshot needs the receiver back.
    let closure = match &function.sig.output {
        ReturnType::Default => quote! { (|| { #body })() },
        ReturnType::Type(_, ty) => quote! { (|| -> #ty { #body })() },
    };

    // The span wraps only the body, never the snapshots.
    let guarded = match &args.span {
        Some(name) => quote! {{
            let __piop_stage_span = ::tracing::info_span!(target: #target, #name);
            let __piop_stage_guard = __piop_stage_span.enter();
            #closure
        }},
        None => quote! { #closure },
    };

    let start = args.snapshot_start.as_ref().map(|phase| {
        let phase = snapshot_phase(phase);
        quote! { self.emit_tracker_snapshot(#phase); }
    });
    let end = args.snapshot_end.as_ref().map(|phase| {
        let phase = snapshot_phase(phase);
        quote! { self.emit_tracker_snapshot(#phase); }
    });

    function.block = syn::parse_quote!({
        #start
        let __piop_stage_output = #guarded;
        #end
        __piop_stage_output
    });

    quote! { #function }.into()
}
