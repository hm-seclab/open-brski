use crate::header::HeaderSet;

pub struct Verified<T> {
    payload: T,
    headers: HeaderSet,
}

impl<T> Verified<T> {
    pub(crate) fn new(payload: T, headers: HeaderSet) -> Self {
        Verified { payload, headers }
    }

    pub fn payload(&self) -> &T {
        &self.payload
    }

    pub fn headers(&self) -> &HeaderSet {
        &self.headers
    }
}
