#[derive(Clone, Copy)]
pub struct Vaddr(usize);

impl std::fmt::Debug for Vaddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("0x{:x}", self.0))
    }
}

impl From<usize> for Vaddr {
    fn from(value: usize) -> Self {
        Self(value)
    }
}
