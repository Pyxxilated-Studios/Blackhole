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
    fn buffer(&self) -> &[u8];

    fn buffer_mut(&mut self) -> &mut [u8];

    fn insert(&mut self, pos: usize, value: u16) -> Result<()>;

    ///
    /// Current position within buffer
    ///
    fn pos(&self) -> usize;

    ///
    /// Grow the internal buffer (if possible)
    ///
    /// # Errors
    /// This will fail if the buffer cannot, or fails to, grow
    ///
    fn grow(&mut self) -> Result<&Self>;

    ///
    /// Step the buffer position forward a specific number of steps
    ///
    /// # Errors
    /// If the number of steps to take pushes the buffer past the
    /// end of its internal state.
    ///
    fn step(&mut self, steps: usize) -> Result<&mut Self> {
        match self
            .pos()
            .checked_add(steps)
            .map(|to| to.cmp(&(u16::MAX as usize)))
        {
            Some(core::cmp::Ordering::Less) => self.seek(self.pos() + steps),
            _ => Err(crate::dns::DNSError::EndOfBuffer),
        }
    }

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
    fn get(&self, pos: usize) -> Result<u8> {
        if pos >= self.buffer().len() {
            Err(crate::dns::DNSError::EndOfBuffer)
        } else {
            Ok(self.buffer()[pos])
        }
    }

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
        T: num_traits::Unsigned + num_traits::PrimInt,
    {
        let bytes = std::mem::size_of::<T>();

        match pos
            .checked_add(bytes)
            .map(|v| (v.cmp(&(u16::MAX as usize)), v.cmp(&self.buffer().len())))
        {
            Some((
                std::cmp::Ordering::Less,
                std::cmp::Ordering::Greater | std::cmp::Ordering::Equal,
            )) => {
                self.grow()?;
            }
            Some((std::cmp::Ordering::Less, std::cmp::Ordering::Less)) => {}
            _ => return Err(crate::dns::DNSError::EndOfBuffer),
        };

        if bytes == 1 {
            self.buffer_mut()[pos] = val.to_u8().unwrap();
        } else {
            for byte in 1..=bytes {
                self.buffer_mut()[pos + byte - 1] = (val >> ((bytes - byte) * u8::BITS as usize)
                    & T::from(0xFF).unwrap())
                .to_u8()
                .unwrap();
            }
        }

        Ok(self)
    }

    ///
    /// Get a range of bytes
    ///
    /// # Errors
    /// If the number of elements wanted causes the buffer to read
    /// past its internal state.
    ///
    fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= self.buffer().len() {
            Err(crate::dns::DNSError::EndOfBuffer)
        } else {
            Ok(&self.buffer()[start..start + len])
        }
    }

    ///
    /// Read a range of bytes
    ///
    /// # Errors
    /// If the number of elements wanted causes the buffer to read
    /// past its internal state.
    ///
    fn read_range(&mut self, len: usize) -> Result<&[u8]> {
        self.step(len)?;
        Ok(&self.buffer()[self.pos() - len..self.pos()])
    }

    ///
    /// Read out an element from the buffer
    ///
    /// # Errors
    /// If the size of the element causes the buffer to read
    /// past its internal state.
    ///
    fn read<T>(&'_ mut self) -> Result<T>
    where
        T: FromBuffer<Self>,
        Self: Sized,
    {
        T::from_buffer(self)
    }

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
        T: WriteTo<'a, Self, Out = Self>,
    {
        val.write_to(self)
    }

    ///
    /// Write a range of elements into the buffer
    ///
    /// # Errors
    /// If the number of elements causes the buffer to write
    /// past its internal state
    ///
    fn write_range<'a, T>(&'a mut self, range: &[T]) -> Result<&'a mut Self>
    where
        Self: Sized,
        T: WriteTo<'a, Self, Out = Self> + Clone,
    {
        range
            .iter()
            .try_fold(self, |out, val| val.clone().write_to(out))
    }
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

macro_rules! impl_from_buffer {
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
impl_from_buffer!(u16, u32, u64, u128, usize);

impl<'a, T: IO, V> WriteTo<'a, T> for &[V]
where
    V: WriteTo<'a, T, Out = T> + Clone,
{
    type Out = T;

    #[inline]
    fn write_to(self, out: &'a mut T) -> Result<&'a mut T> {
        out.write_range(self)
    }
}

impl<'a, T: IO, const N: usize, V> WriteTo<'a, T> for &[V; N]
where
    V: WriteTo<'a, T, Out = T> + Clone,
{
    type Out = T;

    #[inline]
    fn write_to(self, out: &'a mut T) -> Result<&'a mut T> {
        out.write_range(self.as_slice())
    }
}

impl<'a, T: IO, V> WriteTo<'a, T> for Vec<V>
where
    V: WriteTo<'a, T, Out = T> + Clone,
{
    type Out = T;

    #[inline]
    fn write_to(self, out: &'a mut T) -> Result<&'a mut T> {
        out.write_range(self.as_slice())
    }
}
