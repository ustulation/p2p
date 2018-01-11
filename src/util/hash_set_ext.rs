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
            let _ = self.insert(unwrap!(iter.next()));
        }
        let ret = unwrap!(iter.next());
        self.extend(iter);

        Some(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod remove_random {
        use super::*;
        use rand;

        #[test]
        fn it_returns_random_element_and_removes_it_from_the_list() {
            let mut nums = HashSet::new();
            let _ = nums.insert(1u32);
            let _ = nums.insert(2);
            let _ = nums.insert(3);

            let n = nums.remove_random(&mut rand::thread_rng());

            assert!(vec![1, 2, 3].contains(&unwrap!(n)));
            let remaining_nums = nums.iter().cloned().collect::<Vec<u32>>();
            assert!(!remaining_nums.contains(&unwrap!(n)));
        }
    }
}
