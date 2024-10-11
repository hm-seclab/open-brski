use crate::header::HeaderSet;

impl From<HeaderSet> for josekit::jws::JwsHeaderSet {
    fn from(value: HeaderSet) -> Self {
        let mut josekit_set = josekit::jws::JwsHeaderSet::new();
        for (key, value) in value.protected {
            josekit_set.set_claim(&key, Some(value), true);
        }

        for (key, value) in value.unprotected {
            josekit_set.set_claim(&key, Some(value), false);
        }

        josekit_set
    }
}

impl From<josekit::jws::JwsHeaderSet> for HeaderSet {
    fn from(value: josekit::jws::JwsHeaderSet) -> Self {
        let mut header_set = HeaderSet::new();
        for (key, value) in value.claims_set(true) {
            header_set
                .set_claim(key, Some(value.clone()), true)
                .unwrap();
        }

        for (key, value) in value.claims_set(false) {
            header_set
                .set_claim(key, Some(value.clone()), false)
                .unwrap();
        }

        header_set
    }
}

impl From<josekit::jws::JwsHeader> for HeaderSet {
    fn from(value: josekit::jws::JwsHeader) -> Self {
        let mut header_set = HeaderSet::new();

        for (key, value) in value.claims_set() {
            header_set
                .set_claim(key, Some(value.clone()), true)
                .unwrap();
        }

        header_set
    }
}
