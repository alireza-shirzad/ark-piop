//! Instrumentation attributes for ark-piop's prover pipeline.
//!
//! A prover stage reports, on the `bench_stats` target, a span that lasts as
//! long as the stage and a pair of tracker snapshots around it.
//! [`piop_stage`] generates both.

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Error, ItemFn, LitStr, Result, ReturnType, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

/// Tracing target of every span this macro emits. Must equal
/// `ark_piop::prover::tracker::SNARK_PROVER_SPAN_TARGET`, which a proc-macro
/// crate cannot reference.
const BENCH_STATS_TARGET: &str = "bench_stats";

/// Parsed `#[piop_stage(...)]` arguments; any subset may be given.
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

/// The `phase` argument of an `emit_tracker_snapshot` call. A literal
/// containing `{` is a format string over the stage's own parameters
/// (`"bucket_{bucket_index}_start"`); any other is passed as is.
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
///     span           = "compile_piop_subproof",
///     snapshot_start = "compile_start",
///     snapshot_end   = "after_compile_piop_subproof",
/// )]
/// fn compile_piop_subproof(&mut self) -> SnarkResult<Option<Subproof>> {
///     // just the algorithm
/// }
/// ```
///
/// Requires `self` to expose `emit_tracker_snapshot(&self, phase: &str)`
/// whenever a snapshot argument is given.
///
/// The body runs as a closure, so an early `return` or a `?` leaves the
/// closure and the end snapshot fires on every exit path.
///
/// A snapshot walks every materialized poly to sum heap bytes. The span is
/// entered after the start snapshot and dropped before the end one, so that
/// cost stays out of the stage's reported duration.
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

    // The closure carries the function's return type so `?` and `return` in
    // the body resolve as they do in the function. It is not a `move`
    // closure: it reborrows `self`, and the end snapshot needs `self` back.
    let closure = match &function.sig.output {
        ReturnType::Default => quote! { (|| { #body })() },
        ReturnType::Type(_, ty) => quote! { (|| -> #ty { #body })() },
    };

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
