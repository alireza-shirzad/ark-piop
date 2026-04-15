use ark_poly::univariate::DensePolynomial;
/// An LDE is a dense polynomial over a field.
pub type LDE<F> = DensePolynomial<F>;

//TODO: See if we need to implement the `LDE` as a wrapper around `DensePolynomial`, just like `MLE` is a wrapper around `DensePolynomial`. If not needed, we keep it as a type alias.
