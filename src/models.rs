use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Todo {
    pub id: String,
    pub title: String,
    pub completed: bool,
    pub deleted: bool,
    pub updated_at: i64,
    pub node_id: String,
}

#[derive(Deserialize, Debug)]
pub struct CreateTodo {
    pub title: String,
}

#[derive(Deserialize, Debug)]
pub struct UpdateTodo {
    pub completed: bool,
}

#[derive(Deserialize, Debug)]
pub struct PeerReq {
    pub url: String,
}
