mod hash_ext;

pub use self::hash_ext::*;

#[cfg(test)]
#[macro_use]
mod test;

#[cfg(test)]
pub use self::test::*;

/// Tries given expression. Returns boxed future error on failure.
macro_rules! try_bfut {
    ($e:expr) => (match $e {
        Ok(t) => t,
        Err(e) => return future::err(e).into_boxed(),
    })
}
