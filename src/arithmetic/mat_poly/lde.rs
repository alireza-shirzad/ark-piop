use ark_poly::univariate::DensePolynomial;
/// An LDE is a dense polynomial over a field.
pub type LDE<F> = DensePolynomial<F>;

//TODO: decide whether `LDE` needs a wrapper type (like `MLE`) or can stay a type alias.
