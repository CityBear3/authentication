use serde::Deserialize;
#[derive(Deserialize)]
pub struct User {
    pub name: String,
    pub password: String,
}
