use crate::dns::{packet::Buffer, DNSError, Result};

pub trait WriteTo<'a, T: IO> {
    type Out: IO = T;
    ///
    /// Write an element (or series thereof) to an output.
    ///
    /// This is intended to be used for Buffers (or their variants),
    /// where it is nice to chain writes.
    ///
    /// # Errors
    /// This could fail for many reasons, this simplest being that
    /// writing the element to the buffer caused it to overflow its
    /// internal buffer
    ///
    fn write_to(&self, out: &'a mut Self::Out) -> Result<&'a mut Self::Out>;
}

pub trait IO {
    /// Current position within buffer
    fn pos(&self) -> usize;

    /// Step the buffer position forward a specific number of steps
    fn step(&mut self, steps: usize) -> Result<&mut Self>;

    /// Change the buffer position
    fn seek(&mut self, pos: usize) -> Result<&mut Self>;

    /// Get a single byte, without changing the buffer position
    fn get(&mut self, pos: usize) -> Result<u8>;

    /// Set a byte at a specific position
    fn set<T>(&mut self, pos: usize, val: T) -> Result<&mut Self>
    where
        T: num::Unsigned + num::PrimInt;

    /// Get a range of bytes
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]>;

    fn read<'a, T>(&'a mut self) -> Result<T>
    where
        T: TryFrom<&'a mut Self, Error = DNSError> + Default;

    fn write<'a, T>(&'a mut self, val: T) -> Result<&'a mut Self>
    where
        Self: Sized,
        T: WriteTo<'a, Self, Out = Self>;
}

macro_rules! impl_write {
    ( $($t:ty),* ) => {
        $(impl<'a, T: IO> WriteTo<'a, T> for $t {
            fn write_to(&self, out: &'a mut T) -> Result<&'a mut T> {
                if core::any::TypeId::of::<$t>() == core::any::TypeId::of::<u8>() {
                    out.set(out.pos(), *self as u8)?;
                    out.step(1)
                } else {
                    let bytes = core::mem::size_of::<$t>();
                    let val = self.to_be();

                    (0..bytes).try_fold(out, |out, byte| {
                        let v = (val >> (byte * u8::BITS as usize)) as u8 & 0xFF;
                        (*out).write(v)
                    })
                }
            }
        })*
    }
}

macro_rules! impl_try_from {
    ( $($t:ty),* ) => {
        $(impl TryFrom<&mut Buffer> for $t  {
            type Error = DNSError;

            fn try_from(buffer: &mut Buffer) -> Result<$t> {
                let res = <$t>::from_be_bytes(std::array::try_from_fn(|_| buffer.read())?);

                Ok(res)
            }
        })*
    }
}

impl TryFrom<&mut Buffer> for u8 {
    type Error = DNSError;

    fn try_from(buffer: &mut Buffer) -> Result<u8> {
        let res = buffer.get(buffer.pos())?;
        buffer.pos += 1;

        Ok(res)
    }
}

impl_write!(u8, u16, u32, u64, u128, usize);
impl_try_from!(u16, u32, u64, u128, usize);

impl<'a, T: IO> WriteTo<'a, T> for &[u8] {
    fn write_to(&self, out: &'a mut T) -> Result<&'a mut T> {
        self.iter().try_fold(out, |out, &val| out.write(val))
    }
}

impl<'a, T: IO, const N: usize> WriteTo<'a, T> for &[u8; N] {
    fn write_to(&self, out: &'a mut T) -> Result<&'a mut T> {
        self.iter().try_fold(out, |out, &val| out.write(val))
    }
}

impl<'a, T: IO, A> WriteTo<'a, T> for Vec<A>
where
    A: WriteTo<'a, T, Out = T> + Clone,
{
    fn write_to(&self, out: &'a mut T) -> Result<&'a mut T> {
        self.iter().try_fold(out, |out, val| out.write(val.clone()))
    }
}
