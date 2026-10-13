use ark_poly::univariate::DensePolynomial;
pub type LDE<F> = DensePolynomial<F>;

//TODO: decide whether `LDE` needs a wrapper type (like `MLE`) or can stay a type alias.
