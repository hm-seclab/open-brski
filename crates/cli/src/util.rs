use figment::value::magic::RelativePathBuf;

pub fn parse_relative_path_buf(r: &str) -> Result<RelativePathBuf, String> {
    let buf = RelativePathBuf::from(r);

    if buf.relative().exists() {
        Ok(buf)
    } else {
        Err(format!("Path {:?} does not exist", r))
    }
}
