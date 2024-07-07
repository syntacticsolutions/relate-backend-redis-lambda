#[macro_use]
extern crate rocket;

mod api;
mod database;

use crate::api::users::search_users;
use database::initialize_redis;
use rocket::{
    http::{Header, Method},
    local::asynchronous::Client,
    Rocket,
};
use std::str::FromStr;
// use redis::AsyncCommands;
// use redisearch::{Client as RedisSearchClient, SearchQuery, Schema};
use lambda_http::{run, service_fn, Body, Error, Request, Response};

async fn function_handler(event: Request) -> Result<Response<Body>, Error> {
    let client = Client::tracked(rocket())
        .await
        .expect("valid rocket instance");

    // Convert the Lambda request to a Rocket request
    let method = Method::from_str(event.method().as_str()).unwrap();
    let uri = format!(
        "{}{}",
        event
            .uri()
            .path()
            .strip_prefix("/Prod")
            .unwrap_or(event.uri().path()),
        event
            .uri()
            .query()
            .map(|q| format!("?{}", q))
            .unwrap_or_default()
    );

    // Prepare the request to be dispatched
    let mut rocket_req = client.req(method, &uri);

    // Collect headers from the event
    let headers: Vec<(String, String)> = event
        .headers()
        .iter()
        .map(|(header_name, header_value)| {
            (
                header_name.to_string(),
                header_value.to_str().unwrap().to_string(),
            )
        })
        .collect();

    // Add headers to the Rocket request
    for (header_name, header_value) in headers {
        let header = Header::new(header_name, header_value);
        rocket_req = rocket_req.header(header);
    }
    // Add body to the Rocket request
    match event.body() {
        Body::Text(body) => {
            rocket_req = rocket_req.body(body.clone());
        }
        Body::Binary(body) => {
            rocket_req = rocket_req.body(body.clone());
        }
        Body::Empty => {}
    }

    let rocket_resp = rocket_req.dispatch().await;

    // Extract status and headers from the Rocket response
    let status = rocket_resp.status();
    let headers: Vec<Header<'static>> = rocket_resp
        .headers()
        .iter()
        .map(|h| Header::new(h.name().to_string(), h.value().to_string()))
        .collect();

    // Convert the Rocket response to a string body
    let body = rocket_resp.into_string().await.unwrap_or_default();

    // Prepare headers for the Lambda response
    let mut response_builder = Response::builder().status(status.code);

    for header in headers.iter() {
        response_builder = response_builder.header(header.name.as_str(), header.value());
    }

    Ok(response_builder
        .body(Body::Text(body))
        .expect("failed to render response"))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(service_fn(function_handler)).await
}

fn rocket() -> Rocket<rocket::Build> {
    let allowed_origins = rocket_cors::AllowedOrigins::some_exact(&[
        "http://localhost:4321",
        "http://127.0.0.1:4321",
        "https://relate.me",
        "https://www.relate.me",
    ]);

    let redis_config = initialize_redis();

    let cors = rocket_cors::CorsOptions {
        allowed_origins,
        ..Default::default()
    }
    .to_cors()
    .expect("Error creating CORS fairing");

    rocket::build()
        .manage(redis_config)
        .attach(cors)
        .mount("/", routes![search_users])
}
