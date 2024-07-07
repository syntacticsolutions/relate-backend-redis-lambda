pub mod crud;

use std::sync::Arc;

use rocket::{http::Status, serde::json::Json, State};
use serde_json::Value;

use crate::{api::users::crud::find_users_by_search, database::RedisConfig};

#[get("/users/search/<query>")]
pub async fn search_users(
    query: &str,
    config: &State<Arc<RedisConfig>>,
) -> Result<Json<Value>, Status> {
    let config = config.inner().clone();
    find_users_by_search(&query, config).await
}
