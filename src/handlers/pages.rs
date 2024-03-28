use askama::Template;

use crate::User;

#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate;
pub async fn index_handler() -> IndexTemplate {
    IndexTemplate
}

#[derive(Template)]
#[template(path = "chat.html")]
pub struct ChatTemplate;
pub async fn chat_handler(user :User) -> ChatTemplate {
    ChatTemplate
}
