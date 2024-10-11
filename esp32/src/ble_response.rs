use signeable_payload::Signed;


pub struct Response {
    data: Vec<u8>,
}

impl Response {
    pub fn new(data: Vec<u8>) -> Self {
        Response { data }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

pub trait IntoResponse {
    fn into_response(self) -> Response;
}

impl IntoResponse for Vec<u8> {
    fn into_response(self) -> Response {
        Response { data: self }
    }
}

impl IntoResponse for anyhow::Error {
    fn into_response(self) -> Response {
        Response {
            data: format!("{:?}", self).as_bytes().to_vec(),
        }
    }
}

impl IntoResponse for () {
    fn into_response(self) -> Response {
        Response { data: vec![] }
    }
}

impl<T> IntoResponse for Signed<T> {
    fn into_response(self) -> Response {
        Response { data: self.data() }
    }
}

impl<T: IntoResponse> IntoResponse for anyhow::Result<T, anyhow::Error> {
    fn into_response(self) -> Response {
        match self {
            Ok(signed) => signed.into_response(),
            Err(e) => e.into_response(),
        }
    }
}