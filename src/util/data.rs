use rand::{self, Rng};

pub fn random_vec(len: usize) -> Vec<u8> {
    let mut vec = Vec::with_capacity(len);
    unsafe {
        vec.set_len(len);
    }
    rand::thread_rng().fill_bytes(&mut vec[..]);
    vec
}

