pub mod arithmetic;
pub mod errors;
pub mod pcs;
pub mod piop;
pub mod prover;
pub mod setup;
pub mod structs;
pub mod transcript;
pub mod util;
pub mod verifier;
// TODO: This should nbe gated only for tests, however, for some reason it is
// not visible in the tests of col-toolbox
// #[cfg(test)]
pub mod test_utils;

#[macro_export]
macro_rules! add_trace {
    ($fn_name:literal $(, $msg:expr)* $(,)?) => {{
        use ark_std::add_single_trace;
        let msg = format!($($msg),*);
        add_single_trace!(|| format!("{}::{} | {}", module_path!(), $fn_name, msg));
    }};
}
