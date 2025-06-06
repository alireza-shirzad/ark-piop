use ark_ec::AffineRepr;
use ark_ff::{Field, PrimeField};

pub(crate) mod errors;
pub mod ff;
pub mod mat_poly;
pub mod virt_poly;

// Input index
// - `i := (i_0, ...i_{n-1})`,
// - `num_vars := n`
// return three elements:
// - `x0 := (i_1, ..., i_{n-1}, 0)`
// - `x1 := (i_1, ..., i_{n-1}, 1)`
// - `sign := i_0`
#[inline]
pub fn get_index(i: usize, num_vars: usize) -> (usize, usize, bool) {
    let bit_sequence = bit_decompose(i as u64, num_vars);

    // the last bit comes first here because of LE encoding
    let x0 = project(&[[false].as_ref(), bit_sequence[..num_vars - 1].as_ref()].concat()) as usize;
    let x1 = project(&[[true].as_ref(), bit_sequence[..num_vars - 1].as_ref()].concat()) as usize;

    (x0, x1, bit_sequence[num_vars - 1])
}

/// Decompose an integer into a binary vector in little endian.
pub fn bit_decompose(input: u64, num_var: usize) -> Vec<bool> {
    let mut res = Vec::with_capacity(num_var);
    let mut i = input;
    for _ in 0..num_var {
        res.push(i & 1 == 1);
        i >>= 1;
    }
    res
}

pub fn binary_decompose<F: PrimeField>(input: u64, num_var: usize) -> Vec<F> {
    let bit_sequence = bit_decompose(input, num_var);
    bit_sequence.iter().map(|&x| F::from(x as u64)).collect()
}

/// Displays the first 4 digits of a field element
pub fn f_short_str<F: Field>(f: F) -> String {
    let f_str = format!("{:?}", f);
    if f_str.len() <= 4 {
        f_str
    } else {
        format!("{}...", &f_str[0..4])
    }
}

pub fn f_vec_short_str<F: Field>(f: &[F]) -> String {
    let len = f.len();
    if len == 0 {
        "[]".to_string()
    } else if len <= 2 {
        let elements: Vec<String> = f.iter().map(|&elem| f_short_str(elem)).collect();
        format!("[{}]", elements.join(", "))
    } else {
        let first = f_short_str(f[0]);
        let last = f_short_str(f[len - 1]);
        format!("[{}, ..., {}]", first, last)
    }
}

pub fn f_mat_short_str<F: Field>(f: &[Vec<F>]) -> String {
    let len = f.len();
    if len == 0 {
        "[]".to_string()
    } else if len <= 2 {
        let elements: Vec<String> = f.iter().map(|elem| f_vec_short_str(elem)).collect();
        format!("[{}]", elements.join(", "))
    } else {
        let first = f_vec_short_str(&f[0]);
        let last = f_vec_short_str(&f[len - 1]);
        format!("[{}, ..., {}]", first, last)
    }
}

pub fn g1_affine_short_str<G: AffineRepr>(point: &G) -> String
where
    G::ScalarField: PrimeField,
{
    match point.xy() {
        Some((x, y)) => {
            let x_str = f_short_str(x);
            let y_str = f_short_str(y);
            format!("({}, {})", x_str, y_str)
        }
        None => "∞".to_string(), // Point at infinity
    }
}

/// Project a little endian binary vector into an integer.
#[inline]
pub(crate) fn project(input: &[bool]) -> u64 {
    let mut res = 0;
    for &e in input.iter().rev() {
        res <<= 1;
        res += e as u64;
    }
    res
}

#[cfg(test)]
mod test {
    use super::{bit_decompose, get_index, project};
    use ark_std::{rand::RngCore, test_rng};

    #[test]
    fn test_decomposition() {
        let mut rng = test_rng();
        for _ in 0..100 {
            let t = rng.next_u64();
            let b = bit_decompose(t, 64);
            let r = project(&b);
            assert_eq!(t, r)
        }
    }

    #[test]
    fn test_get_index() {
        let a = 0b1010;
        let (x0, x1, sign) = get_index(a, 4);
        assert_eq!(x0, 0b0100);
        assert_eq!(x1, 0b0101);
        assert!(sign);

        let (x0, x1, sign) = get_index(a, 5);
        assert_eq!(x0, 0b10100);
        assert_eq!(x1, 0b10101);
        assert!(!sign);

        let a = 0b1111;
        let (x0, x1, sign) = get_index(a, 4);
        assert_eq!(x0, 0b1110);
        assert_eq!(x1, 0b1111);
        assert!(sign);
    }
}
