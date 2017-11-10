use priv_prelude::*;

pub trait HashSetExt<T: Eq + Hash> {
    fn remove_random<R: Rng>(&mut self, rng: &mut R) -> Option<T>;
}

impl<T: Eq + Hash> HashSetExt<T> for HashSet<T> {
    fn remove_random<R: Rng>(&mut self, rng: &mut R) -> Option<T> {
        let n = self.len();
        if n == 0 {
            return None;
        }
        let i = rng.gen_range(0, n);

        let me = mem::replace(self, HashSet::with_capacity(n));
        let mut iter = me.into_iter();

        for _ in 0..i {
            self.insert(unwrap!(iter.next()));
        }
        let ret = unwrap!(iter.next());
        self.extend(iter);

        Some(ret)
    }
}
