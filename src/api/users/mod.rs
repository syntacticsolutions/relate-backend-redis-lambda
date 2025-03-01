pub mod crud;

use std::sync::Arc;

use rocket::{http::Status, serde::json::Json, State};
use serde_json::Value;

use crate::{api::users::crud::{find_users_by_search, get_user_by_id}, database::RedisConfig};

#[get("/users/search/<query>")]
pub async fn search_users(
    query: &str,
    config: &State<Arc<RedisConfig>>,
) -> Result<Json<Value>, Status> {
    let config = config.inner().clone();
    find_users_by_search(&query, config).await
}

#[get("/user/<user_id>")]
pub async fn get_user(
    user_id: &str,
    config: &State<Arc<RedisConfig>>,
) -> Result<Json<Value>, Status> {
    let config = config.inner().clone();
    get_user_by_id(user_id, config).await.map(Json)
}