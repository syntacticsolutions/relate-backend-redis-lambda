// use redisearch::{Client as RedisSearchClient, SearchQuery, Schema};

use regex::Regex;
use rocket::{http::Status, serde::json::Json};
use serde_json::{json, Value as JSONValue};
use std::sync::Arc;

use crate::database::{get_secure_connection, RedisConfig};

pub async fn find_users_by_search(
    query: &str,
    config: Arc<RedisConfig>,
) -> Result<Json<JSONValue>, Status> {
    let mut conn = get_secure_connection(config)
        .await
        .map_err(|_| Status::InternalServerError)?;
    // Regex pattern to remove non-alphanumeric characters from the edges
    let re = Regex::new(r"(?m)^\s+|\s+$").unwrap();
    let sanitized = re.replace_all(query, "").to_string(); // Remove leading and trailing whitespace

    // Format the query for fuzzy search, preserving internal whitespace
    let formatted_query = format!("*{}*", sanitized.replace(" ", "* *"));

    let results: redis::Value = redis::cmd("FT.SEARCH")
        .arg("userIndex")
        .arg(formatted_query.clone() + "~2")
        .query_async(&mut conn)
        .await
        .map_err(|_| Status::InternalServerError)?;

    println!("Redis search results: {:?}", results);

    let mut users: Vec<JSONValue> = Vec::new();

    if let redis::Value::Bulk(items) = results {
        for item in items.into_iter() {
            if let redis::Value::Bulk(inner_items) = item {
                if inner_items.len() != 2 {
                    eprintln!(
                        "Expected 2 items in inner Bulk value, found {:?}",
                        inner_items
                    );
                    continue; // Skip this item if it doesn't match expected structure
                }

                let value_data = &inner_items[1];

                if let redis::Value::Data(value_data) = value_data {
                    let json_str = String::from_utf8_lossy(&value_data).to_string();
                    println!("JSON String: {}", json_str);

                    match serde_json::from_str::<JSONValue>(&json_str) {
                        Ok(json_value) => {
                            println!("JSON Value: {:?}", json_value);
                            users.push(json_value);
                        }
                        Err(err) => {
                            eprintln!("Error parsing JSON: {}", err);
                            return Err(Status::InternalServerError);
                        }
                    }
                } else {
                    continue; // Skip this item if it doesn't match expected structure
                }
            } else {
                eprintln!("Expected Bulk value, found {:?}", item);
                continue; // Skip this item if it doesn't match expected structure
            }
        }
    }

    println!("Users: {:?}", users);

    Ok(Json(json!(users)))
}

pub async fn get_user_by_id(
    user_id: &str,
    config: Arc<RedisConfig>,
) -> Result<JSONValue, Status> {
    let mut conn = get_secure_connection(config)
        .await
        .map_err(|_| Status::InternalServerError)?;

    // Directly fetch the user JSON by ID
    let result: Option<String> = redis::cmd("GET")
        .arg(format!("user:{}", user_id))
        .query_async(&mut conn)
        .await
        .map_err(|_| Status::InternalServerError)?;

    // If user is found, return it as JSON
    match result {
        Some(json_str) => {
            match serde_json::from_str::<JSONValue>(&json_str) {
                Ok(json_value) => Ok(json_value),
                Err(_) => Err(Status::InternalServerError), // Invalid JSON format in Redis
            }
        }
        None => Err(Status::NotFound), // User not found
    }
}
