use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{digest::KeyInit, Hmac};
use jwt::{Header, SignWithKey, Token};
use lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use std::env;

#[derive(Debug, Deserialize, Serialize)]
struct Resource {
    dashboard: u32,
}

#[derive(Debug, Deserialize, Serialize)]
struct Params {
    id: u32,
}

#[derive(Debug, Deserialize, Serialize)]
struct UnsignedToken {
    resource: Resource,
    params: Params,
    exp: u64,
}

impl UnsignedToken {
    fn new(id: u32, dashboard: u32) -> Self {
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let expiration = since_the_epoch.as_secs() + 600;

        UnsignedToken {
            resource: Resource { dashboard },
            params: Params { id },
            exp: expiration,
        }
    }
}

async fn function_handler(event: Request) -> Result<Response<Body>, Error> {
    let dashboard = event
        .query_string_parameters_ref()
        .and_then(|params| params.first("dashboard"))
        .unwrap();

    let header: Header = Default::default();

    let id = 1;

    let token = UnsignedToken::new(id, dashboard.parse().unwrap());

    let unsigned_token = Token::new(header, token);

    let metabase_key =
        env::var("METABASE_KEY").expect("SECRET_KEY not set in environment variables");

    let metabase_url =
        env::var("METABASE_URL").expect("METABASE_URL not set in environment variables");

    let key: Hmac<Sha256> =
        Hmac::new_from_slice(metabase_key.as_bytes()).map_err(|_e| "Invalid key")?;

    let signed_token = unsigned_token
        .sign_with_key(&key)
        .map_err(|_e| "Sign error")?;

    let url = format!(
        "https://{}/embed/dashboard/{}#bordered=true&titled=true",
        metabase_url,
        signed_token.as_str()
    );

    let resp = Response::builder()
        .status(200)
        .header("content-type", "text/html")
        .body(url.into())
        .map_err(Box::new)?;
    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

    run(service_fn(function_handler)).await
}
