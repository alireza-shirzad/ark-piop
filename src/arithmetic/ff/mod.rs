/// Convert a vector of integers to field elements, through `i64`.
#[macro_export]
macro_rules! to_field_vec {
    ($vec:expr, $field:ty) => {
        $vec.iter()
            .map(|x| <$field>::from(*x as i64))
            .collect::<Vec<$field>>()
    };
}
