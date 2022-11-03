use std::fmt::Debug;

use crate::dns::Result;

pub trait FromBuffer<I: IO> {
    /// Build an item from a buffer
    ///
    /// # Errors
    /// This will fail if reading from the buffer causes it to
    /// read past the end of its internal state
    ///
    fn from_buffer(buffer: &mut I) -> Result<Self>
    where
        I: IO,
        Self: Sized;
}

pub trait WriteTo<'a, T: IO> {
    type Out: IO;

    ///
    /// Write an element (or series thereof) to an output.
    ///
    /// This is intended to be used for Buffers (or their variants),
    /// where it is nice to chain writes.
    ///
    /// # Errors
    /// This could fail for many reasons, the simplest being that
    /// writing the element to the buffer caused it to overflow its
    /// internal buffer
    ///
    fn write_to(self, out: &'a mut Self::Out) -> Result<&'a mut Self::Out>;
}

pub trait IO {
    ///
    /// Current position within buffer
    ///
    fn pos(&self) -> usize;

    ///
    /// Step the buffer position forward a specific number of steps
    ///
    /// # Errors
    /// If the number of steps to take pushes the buffer past the
    /// end of its internal state.
    ///
    fn step(&mut self, steps: usize) -> Result<&mut Self>;

    ///
    /// Change the buffer position
    ///
    /// # Errors
    /// If the position is past the end of the buffers internal
    /// state.
    ///
    fn seek(&mut self, pos: usize) -> Result<&mut Self>;

    ///
    /// Get a single byte, without changing the buffer position
    ///
    /// # Errors
    /// If the position is past the end of the buffers internal
    /// state.
    ///
    fn get(&self, pos: usize) -> Result<u8>;

    ///
    /// Set a byte at a specific position
    ///
    /// # Errors
    /// If the position being set, or in conjunction with the
    /// size of the element, is past the end of the buffers
    /// internal state.
    ///
    fn set<T>(&mut self, pos: usize, val: T) -> Result<&mut Self>
    where
        T: num::Unsigned + num::PrimInt;

    ///
    /// Get a range of bytes
    ///
    /// # Errors
    /// If the number of elements wanted causes the buffer to read
    /// past its internal state.
    ///
    fn get_range(&self, start: usize, len: usize) -> Result<&[u8]>;

    ///
    /// Read a range of bytes
    ///
    /// # Errors
    /// If the number of elements wanted causes the buffer to read
    /// past its internal state.
    ///
    fn read_range(&mut self, len: usize) -> Result<&[u8]>;

    ///
    /// Read out an element from the buffer
    ///
    /// # Errors
    /// If the size of the element causes the buffer to read
    /// past its internal state.
    ///
    fn read<T>(&'_ mut self) -> Result<T>
    where
        T: FromBuffer<Self> + Default,
        Self: Sized;

    ///
    /// Write an element into the buffer
    ///
    /// # Errors
    /// If the size of the element causes the buffer to write
    /// past its internal state.
    ///
    fn write<'a, T>(&'a mut self, val: T) -> Result<&'a mut Self>
    where
        Self: Sized,
        T: WriteTo<'a, Self, Out = Self> + Debug;
}

macro_rules! impl_write {
    ( $($t:ty),* ) => {
        $(impl<'a, T: IO> WriteTo<'a, T> for $t {
            type Out = T;

            fn write_to(self, out: &'a mut T) -> Result<&'a mut T> {
                if core::any::TypeId::of::<$t>() == core::any::TypeId::of::<u8>() {
                    out.set(out.pos(), self as u8)?;
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
        $(impl<I: IO> FromBuffer<I> for $t  {
            #[inline]
            fn from_buffer(buffer: &mut I) -> Result<$t> {
                let res = <$t>::from_be_bytes(std::array::try_from_fn(|_| buffer.read())?);

                Ok(res)
            }
        })*
    }
}

impl<I: IO> FromBuffer<I> for u8 {
    fn from_buffer(buffer: &mut I) -> Result<u8> {
        let res = buffer.get(buffer.pos())?;
        buffer.step(1)?;

        Ok(res)
    }
}

impl_write!(u8, u16, u32, u64, u128, usize);
impl_try_from!(u16, u32, u64, u128, usize);

impl<'a, T: IO> WriteTo<'a, T> for &[u8] {
    type Out = T;

    #[inline]
    fn write_to(self, out: &'a mut T) -> Result<&'a mut T> {
        self.iter().try_fold(out, |out, &val| out.write(val))
    }
}

impl<'a, T: IO, const N: usize> WriteTo<'a, T> for &[u8; N] {
    type Out = T;

    #[inline]
    fn write_to(self, out: &'a mut T) -> Result<&'a mut T> {
        self.iter().try_fold(out, |out, &val| out.write(val))
    }
}

impl<'a, T: IO, E> WriteTo<'a, T> for Vec<E>
where
    E: WriteTo<'a, T, Out = T> + Clone + Debug,
{
    type Out = T;

    #[inline]
    fn write_to(self, out: &'a mut T) -> Result<&'a mut T> {
        self.iter().try_fold(out, |out, val| out.write(val.clone()))
    }
}

impl<'a, T: IO, E> WriteTo<'a, T> for &Vec<E>
where
    E: WriteTo<'a, T, Out = T> + Clone + Debug,
{
    type Out = T;

    #[inline]
    fn write_to(self, out: &'a mut T) -> Result<&'a mut T> {
        self.iter().try_fold(out, |out, val| out.write(val.clone()))
    }
}
