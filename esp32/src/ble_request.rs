pub struct RequestWithState<S: Send + Sync + 'static> {
    data: Vec<u8>,
    state: S
}

impl<S: Send + Sync + 'static> RequestWithState<S> {
    pub fn new(data: Vec<u8>, state: S) -> Self {
        RequestWithState { data, state }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn state(&self) -> &S {
        &self.state
    }
}