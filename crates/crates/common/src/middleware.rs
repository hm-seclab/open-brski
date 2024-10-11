pub async fn log_request_size(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> impl axum::response::IntoResponse {
    // Extract the content length from the request headers if available
    if let Some(content_length) = request.headers().get(axum::http::header::CONTENT_LENGTH) {
        if let Ok(size) = content_length.to_str() {
            let uri = request.uri();
            tracing::info!("Requested {} - Payload size: {} bytes", uri, size);
        }
    } else {
        tracing::info!("Request size: unknown (no Content-Length header)");
    }

    // Proceed to the next layer
    next.run(request).await
}
