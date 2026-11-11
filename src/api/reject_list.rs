use super::*;

pub struct RejectListClient {
    client: RestClient,
    base_url: String,
}

impl RejectListClient {
    pub(crate) fn new(base_url: &str) -> Result<Self, Error> {
        let client = RestClient::builder()
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT))
            .timeout(Duration::from_secs(READ_WRITE_TIMEOUT))
            .build()?;
        Ok(Self {
            client,
            base_url: base_url.to_string(),
        })
    }

    fn req_err(e: impl std::fmt::Display) -> Error {
        Error::RejectListService {
            details: e.to_string(),
        }
    }

    pub(crate) fn get_reject_list(&self) -> Result<String, Error> {
        const MAX_BODY_BYTES: u64 = 1024 * 1024;
        let response = self
            .client
            .get(&self.base_url)
            .send()
            .map_err(Self::req_err)?;
        if response
            .content_length()
            .is_some_and(|len| len > MAX_BODY_BYTES)
        {
            return Err(Self::req_err("response body exceeds the size limit"));
        }
        let status = response.status();
        if !status.is_success() {
            return Err(Self::req_err(format!("HTTP status {status}")));
        }
        let text = response.text().map_err(Self::req_err)?;
        if text.len() as u64 > MAX_BODY_BYTES {
            return Err(Self::req_err("response body exceeds the size limit"));
        }
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_reject_list_error() {
        // network error
        let client = RejectListClient::new("http://127.0.0.1:1").unwrap();
        let result = client.get_reject_list().unwrap_err();
        assert_matches!(result, Error::RejectListService { .. });

        // content-length mismatch (truncated body)
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-length", "100")
            .with_body(&[0xFFu8, 0xFEu8][..])
            .create();
        let client = RejectListClient::new(&server.url()).unwrap();
        let result = client.get_reject_list().unwrap_err();
        assert_matches!(result, Error::RejectListService { .. });
        mock.assert();
    }
}
