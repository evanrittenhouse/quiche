pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BufferTooShortError(usize),
    InvalidState,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::BufferTooShortError(v) => {
                write!(f, "BufferTooShortError required={v}")
            },

            _ => write!(f, "Other error"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct VarintTlv<'a> {
    octets: octets::Octets<'a>,
    ty: Option<u64>,
    len: Option<u64>,
    value: Option<octets::Octets<'a>>,
}

impl<'a> VarintTlv<'a> {
    /// Creates a `VarintTlv` from the given slice, without copying.
    ///
    /// Since the `VarintTlv` is immutable, the input slice needs to be
    /// immutable.
    pub fn with_slice(buf: &'a [u8]) -> Result<Self> {
        if buf.is_empty() {
            return Err(Error::BufferTooShortError(1));
        }

        Ok(VarintTlv {
            octets: octets::Octets::with_slice(buf),
            ty: None,
            len: None,
            value: None,
        })
    }

    #[allow(dead_code)]
    pub fn with_ty(ty: u64, buf: &'a [u8]) -> Result<Self> {
        if buf.is_empty() {
            return Err(Error::BufferTooShortError(1));
        }

        Ok(VarintTlv {
            octets: octets::Octets::with_slice(buf),
            ty: Some(ty),
            len: None,
            value: None,
        })
    }

    #[allow(dead_code)]
    pub fn with_ty_len(ty: u64, len: u64, buf: &'a [u8]) -> Result<Self> {
        if buf.is_empty() {
            return Err(Error::BufferTooShortError(1));
        }

        Ok(VarintTlv {
            octets: octets::Octets::with_slice(buf),
            ty: Some(ty),
            len: Some(len),
            value: None,
        })
    }

    /// Returns the current offset of the buffer.
    pub fn off(&self) -> usize {
        self.octets.off()
    }

    pub fn ty(&mut self) -> Result<u64> {
        if let Some(ty) = self.ty {
            return Ok(ty);
        }

        if self.octets.is_empty() {
            return Err(Error::BufferTooShortError(1));
        }

        match self.octets.get_varint() {
            Ok(v) => {
                self.ty = Some(v);

                Ok(v)
            },
            Err(_e) => {
                let first = self.octets.peek_u8().unwrap();

                let len = octets::varint_parse_len(first);
                Err(Error::BufferTooShortError(len - self.octets.cap()))
            },
        }
    }

    pub fn len(&mut self) -> Result<u64> {
        if self.ty.is_none() {
            return Err(Error::InvalidState);
        }

        if let Some(len) = self.len {
            return Ok(len);
        }

        if self.octets.is_empty() {
            return Err(Error::BufferTooShortError(1));
        }

        match self.octets.get_varint() {
            Ok(v) => {
                self.len = Some(v);

                Ok(v)
            },
            Err(_e) => {
                let first = self.octets.peek_u8().unwrap();

                let len = octets::varint_parse_len(first);
                Err(Error::BufferTooShortError(len - self.octets.cap()))
            },
        }
    }

    pub fn val(&mut self) -> Result<octets::Octets> {
        if let Some(v) = &self.value {
            return Ok(octets::Octets::with_slice(v.buf()));
        }

        let len = match self.len {
            Some(v) => v as usize,
            None => return Err(Error::InvalidState),
        };

        match self.octets.get_bytes(len) {
            Ok(v) => {
                let ret = octets::Octets::with_slice(v.buf());
                self.value = Some(v);
                Ok(ret)
            },

            Err(_) => Err(Error::BufferTooShortError(len - self.octets.cap())),
        }
    }

    pub fn reset(&mut self) {
        self.ty = None;
        self.len = None;
        self.value = None;
    }

    #[allow(dead_code)]
    pub fn skip(&mut self, skip: usize) -> Result<()> {
        match self.octets.skip(skip) {
            Ok(()) => Ok(()),
            Err(_) => Err(Error::BufferTooShortError(skip - self.octets.cap())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_quiche::quiche;

    #[test]
    fn test_tlv() {
        let mut d = [42; 9999];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let frame_in_1 = quiche::h3::frame::Frame::Data {
            payload: vec![1, 2, 3],
        };
        let len = frame_in_1.to_bytes(&mut b).unwrap();

        let frame_in_2 = quiche::h3::frame::Frame::Data {
            payload: vec![4, 5, 6],
        };
        let len = frame_in_2.to_bytes(&mut b).unwrap();

        drop(b);

        let mut tlv = VarintTlv::with_slice(&d).unwrap();
        assert_eq!(tlv.ty().unwrap(), 0);
        assert_eq!(tlv.len().unwrap(), 3);

        let val = tlv.val().unwrap();

        assert_eq!(val.len(), 3);
        assert_eq!(val.buf(), [1, 2, 3]);

        let frame_out = quiche::h3::frame::Frame::from_bytes(
            tlv.ty.unwrap(),
            tlv.len.unwrap(),
            tlv.val().unwrap().buf(),
        )
        .unwrap();

        assert_eq!(frame_in_1, frame_out);

        tlv.reset();

        assert_eq!(tlv.ty().unwrap(), 0);
        assert_eq!(tlv.len().unwrap(), 3);

        let val = tlv.val().unwrap();

        assert_eq!(val.len(), 3);
        assert_eq!(val.buf(), [4, 5, 6]);

        let frame_out = quiche::h3::frame::Frame::from_bytes(
            tlv.ty.unwrap(),
            tlv.len.unwrap(),
            tlv.val().unwrap().buf(),
        )
        .unwrap();

        assert_eq!(frame_in_2, frame_out);
    }
}
