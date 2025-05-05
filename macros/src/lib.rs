use proc_macro::TokenStream;
use quote::quote;
use syn::{
    DeriveInput, Expr, ExprLit, ItemFn, Lit, Token, parse_macro_input, punctuated::Punctuated,
};

#[proc_macro_attribute]
pub fn timed(attr: TokenStream, item: TokenStream) -> TokenStream {
    let extra_args = parse_macro_input!(attr with Punctuated::<Expr, Token![,]>::parse_terminated);
    let input = parse_macro_input!(item as ItemFn);

    let fn_name = input.sig.ident.to_string();
    let block = &input.block;
    let vis = &input.vis;
    let sig = &input.sig;
    let attrs = &input.attrs;

    // Build formatting expressions
    let formatted_parts: Vec<_> = extra_args
        .iter()
        .map(|expr| match expr {
            Expr::Lit(ExprLit {
                lit: Lit::Str(s), ..
            }) => quote! { #s },
            _ => quote! { &format!("{:?}", #expr) },
        })
        .collect();

    let timer_code = if formatted_parts.is_empty() {
        quote! {
            use ark_std::{start_timer, end_timer};
            let timer = start_timer!(|| concat!(module_path!(), "::", #fn_name));
        }
    } else {
        quote! {
            use ark_std::{start_timer, end_timer};
            let timer = start_timer!(|| {
                let extra = [#(#formatted_parts),*].concat();
                format!("{}::{} | {}", module_path!(), #fn_name, extra)
            });
        }
    };

    let expanded = quote! {
        #(#attrs)*
        #vis #sig {
            #timer_code
            let result = (|| #block)();
            end_timer!(timer);
            result
        }
    };

    expanded.into()
}
