use actix_web::web;
mod handlers;

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg
    .route("/users", web::get().to(handlers::fetch_users))
    .route("/create-user", web::post().to(handlers::create_user))
    .route("/login", web::post().to(handlers::login))
    .route("/", web::get().to(handlers::hello));
}