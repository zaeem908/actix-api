use crate::auth::UserDataStruct;
use crate::authorization::{LoginForm, UserController};
use crate::db::AppState;
use actix_web::web;
use actix_web::web::Data;
use actix_web::HttpResponse;

pub async fn login_handler(form: web::Json<LoginForm>, state: Data<AppState>) -> HttpResponse {
    let db = &state.db; // extracted pg pool from appstate
    let result = form.login(&db).await;

    match result {
        Ok(token) => HttpResponse::Ok().json(token),
        Err(err) => {
            eprintln!("Database error: {:?}", err);
            HttpResponse::InternalServerError().json("Internal Server Error")
        }
    }
}

pub async fn fetch_users_handler(data: Data<AppState>) -> HttpResponse {
    match UserController::fetch_users(data).await {
        Ok(x) => HttpResponse::Ok().json(x),
        Err(err_msg) => {
            println!("error : {:?}", err_msg);
            HttpResponse::InternalServerError().json("failed to fetch users")
        }
    }
}

pub async fn create_user_handler(
    user_data: actix_web::web::Json<UserDataStruct>,
    data: Data<AppState>,
) -> HttpResponse {
    let result = UserController::create_user(user_data.into_inner(), &data).await;

    match result {
        Ok(_) => HttpResponse::Ok().body("User created successfully"),
        Err(err) => {
            eprintln!("Database error: {:?}", err);
            HttpResponse::InternalServerError().json("Internal Server Error")
        }
    }
}

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .route("/", web::get().to(fetch_users_handler))
            .route("/", web::post().to(create_user_handler))
            .route("/login", web::post().to(login_handler)),
    );
}
