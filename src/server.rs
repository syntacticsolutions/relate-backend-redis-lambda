#[macro_use]
extern crate rocket;

use crate::api::users::search_users;
use crate::database::initialize_redis;
use rocket::Rocket;
use rocket_cors::{AllowedOrigins, CorsOptions};

mod api;
mod database;

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    let rocket = build_rocket();
    rocket.launch().await?;
    Ok(())
}

pub fn build_rocket() -> Rocket<rocket::Build> {
    let allowed_origins = AllowedOrigins::all();

    let redis_config = initialize_redis();

    let cors = CorsOptions {
        allowed_origins,
        ..Default::default()
    }
    .to_cors()
    .expect("Error creating CORS fairing");

    env_logger::init();

    rocket::build()
        .manage(redis_config)
        .attach(cors)
        .mount("/", routes![search_users])
}
