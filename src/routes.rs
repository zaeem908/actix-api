use crate::handlers::UserController;
use actix_web::web;

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/users", web::get().to(UserController::fetch_users))
        .route(
            "/create-user",
            web::post().to(UserController::create_user_route),
        )
        .route("/login", web::post().to(UserController::login))
        .route("/", web::get().to(UserController::hello));
}
