use core::fmt;

// TODO: Feature gate these for print-trace only
struct ShortDisplayToStringAdapter<'a>(&'a dyn ShortDisplay);

impl<'a> fmt::Display for ShortDisplayToStringAdapter<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt_short(f)
    }
}
pub trait ShortDisplay {
    fn fmt_short(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;

    fn to_short_string(&self) -> String
    where
        Self: Sized,
    {
        format!("{}", ShortDisplayToStringAdapter(self))
    }
}

pub fn short_vec_str<T: ShortDisplay>(v: &[T]) -> String {
    let len = v.len();
    match len {
        0 => "[]".to_string(),
        1 => format!("[{}]", v[0].to_short_string()),
        2 => format!("[{}, {}]", v[0].to_short_string(), v[1].to_short_string()),
        _ => format!(
            "[{}, ..., {}]",
            v[0].to_short_string(),
            v[len - 1].to_short_string()
        ),
    }
}
