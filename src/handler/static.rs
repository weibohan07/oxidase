pub mod r#static {
    use crate::config::r#static::{
        EvilDirStrategyIndexExists,
        EvilDirStrategyIndexMissing,
        IndexStrategy,
        StaticService,
    };
    use crate::handler::ServiceHandler;

    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::{body, http};
    use mime_guess::from_path;
    use percent_encoding::percent_decode_str;
    use std::fs;
    use std::path::{Component, Path, PathBuf};

    impl ServiceHandler for StaticService {
        fn handle_request(
            &self,
            req: &mut http::Request<body::Incoming>,
        ) -> http::Response<Full<Bytes>> {
            let head_only = req.method() == &http::Method::HEAD;

            let url_path_raw = req.uri().path();
            let is_url_path_dir = url_path_raw.ends_with('/');
            eprintln!("Requested path: {} (is dir: {})", url_path_raw, is_url_path_dir);

            let rel = match url_path_to_relative(url_path_raw) {
                Ok(p) => p,
                Err(msg) => return bad_request(msg),
            };

            let base_dir_path = Path::new(&self.source_dir);
            let target_path = base_dir_path.join(&rel);
            let is_target_dir = is_existing_dir(&target_path);
            let is_target_index =
                !is_url_path_dir
                && target_path.file_name().map_or(false, |f| f == self.file_index.as_str());

            eprintln!("Mapped to path: {:?} (is dir: {}, is index: {})", target_path, is_target_dir, is_target_index);

            if is_target_index {
                match &self.index_strategy {
                    IndexStrategy::Redirect { code } =>
                        return redirect_to(&location_cur_dir(req), *code),
                    IndexStrategy::NotFound =>
                        return nearest_404(base_dir_path, &target_path, &self.file_404, head_only),
                    IndexStrategy::ServeIndex => {},
                }
            }

            let target_file_path = if is_url_path_dir {
                target_path.join(&self.file_index)
            } else {
                target_path.clone()
            };

            eprintln!("Mapped to file: {:?}", target_file_path);

            if let Ok(body) = std::fs::read(&target_file_path) {
                eprintln!("Serving file: {:?}", target_file_path);
                return with_ct(hyper::http::StatusCode::OK, &target_file_path, body, head_only);
            }

            if is_target_dir && !is_url_path_dir {
                let index_file_path = target_path.join(&self.file_index);
                let has_index_file = index_file_path.is_file();

                return if has_index_file {
                    match &self.evil_dir_strategy.if_index_exists {
                        EvilDirStrategyIndexExists::ServeIndex =>
                            serve_file_or_404(base_dir_path, &index_file_path, &self.file_404, head_only),
                        EvilDirStrategyIndexExists::Redirect { code } =>
                            redirect_to(&location_with_slash(req), *code),
                        EvilDirStrategyIndexExists::NotFound =>
                            nearest_404(base_dir_path, &target_path, &self.file_404, head_only),
                    }
                } else {
                    match &self.evil_dir_strategy.if_index_missing {
                        EvilDirStrategyIndexMissing::Redirect { code } =>
                            redirect_to(&location_with_slash(req), *code),
                        EvilDirStrategyIndexMissing::NotFound =>
                            nearest_404(base_dir_path, &target_path, &self.file_404, head_only),
                    }
                }
            }

            nearest_404(base_dir_path, &target_file_path, &self.file_404, head_only)
        }
    }

    /// Convert URL path (starts with '/') to a relative path, disallowing ".." escapes and performing % decoding.
    fn url_path_to_relative(url_path: &str) -> Result<PathBuf, &'static str> {
        if !url_path.starts_with('/') {
            return Err("path must start with '/'");
        }
        
        let decoded = percent_decode_str(url_path).decode_utf8_lossy();

        let mut result = PathBuf::new();
        for comp in Path::new(decoded.trim_start_matches('/')).components() {
            match comp {
                Component::CurDir => {}
                Component::ParentDir => {
                    if !result.pop() {
                        return Err("Path traversal not allowed");
                    }
                }
                Component::Normal(seg) => {
                    result.push(seg);
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err("Absolute path not allowed");
                }
            }
        }

        Ok(result)
    }

    fn is_existing_dir(p: &Path) -> bool {
        fs::metadata(p).map(|md| md.is_dir()).unwrap_or(false)
    }

    fn cascade_404_path(base: &Path, start: &Path, file_404: &str) -> Option<PathBuf> {
        let mut dir = start.parent().unwrap_or(base);

        loop {
            if !dir.starts_with(base) { break; }

            let candidate = dir.join(file_404);
            if candidate.is_file() { return Some(candidate); }
            match dir.parent() {
                Some(parent) => dir = parent,
                None => break,
            }
        }

        None
    }

    fn make_response(status: http::StatusCode, body: &[u8]) -> http::Response<Full<Bytes>> {
        http::Response::builder()
            .status(status)
            .body(Full::new(Bytes::copy_from_slice(body)))
            .unwrap()
    }

    fn nearest_404(
        base: &Path,
        start: &Path,
        file_404: &str,
        head_only: bool,
    ) -> http::Response<Full<Bytes>> {
        let nf = cascade_404_path(base, start, file_404)
            .or_else(|| {
                let global = base.join(file_404);
                if global.is_file() { Some(global) } else { None }
            });

        match nf {
            Some(p) => {
                match fs::read(&p) {
                    Ok(body) =>
                        return with_ct(http::StatusCode::NOT_FOUND, &p, body, head_only),
                    Err(_) => {},
                }
            }
            None => {},
        }

        make_response(http::StatusCode::NOT_FOUND, b"404 Not Found")
    }

    fn with_ct(
        status: http::StatusCode,
        path: &Path,
        content: Vec<u8>,
        head_only: bool,
    ) -> http::Response<Full<Bytes>> {
        let mime = from_path(path).first_or_octet_stream();
        if head_only {
            http::Response::builder()
                .status(status)
                .header(http::header::CONTENT_TYPE, mime.as_ref())
                .header(http::header::CONTENT_LENGTH, content.len().to_string())
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            http::Response::builder()
                .status(status)
                .header(http::header::CONTENT_TYPE, mime.as_ref())
                .body(Full::new(Bytes::from(content)))
                .unwrap()
        }
    }

    fn serve_file_or_404(
        base: &Path,
        path: &Path,
        file_404: &str,
        head_only: bool,
    ) -> http::Response<Full<Bytes>> {
        match std::fs::read(path) {
            Ok(body) => with_ct(hyper::http::StatusCode::OK, path, body, head_only),
            Err(_) => nearest_404(base, path, file_404, head_only),
        }
    }

    fn redirect_to(
        location: &str,
        code: u16,
    ) -> http::Response<Full<Bytes>> {
        let status = http::StatusCode::from_u16(code)
            .unwrap_or(http::StatusCode::PERMANENT_REDIRECT);

        http::Response::builder()
            .status(status)
            .header(
                http::header::LOCATION,
                http::HeaderValue::from_str(&location)
                    .unwrap_or_else(|_| http::HeaderValue::from_static("/")),
            )
            .body(Full::new(Bytes::new()))
            .unwrap()
    }

    fn location_with_slash(req: &http::Request<body::Incoming>) -> String {
        let mut location = req.uri().path().to_string();
        if !location.ends_with('/') { location.push('/'); }
        if let Some(query) = req.uri().query() {
            location.push('?');
            location.push_str(query);
        }
        location
    }

    fn location_cur_dir(req: &http::Request<body::Incoming>) -> String {
        let mut location = req.uri().path().to_string();
        location = location.trim_end_matches(|c| c != '/').to_string();
        if let Some(query) = req.uri().query() {
            location.push('?');
            location.push_str(query);
        }
        location
    }

    fn bad_request(msg: &'static str) -> http::Response<Full<Bytes>> {
        let mut resp
            = http::Response::new(Full::new(Bytes::from_static(msg.as_bytes())));
        *resp.status_mut() = http::StatusCode::BAD_REQUEST;
        resp
    }
}
