use crate::auth::UserDataStruct;
use crate::authorization::{
    Exercises,
    ForgotPassword,
    LoginForm,
    NewUserPlan, //WorkoutPlan,
    NewUserProfile,
    ResetPassword,
    UserController,
};
use crate::db::AppState;
use actix_web::web;
use actix_web::web::Data;
use actix_web::HttpResponse;

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

pub async fn forgot_password_handler(
    form: web::Json<ForgotPassword>,
    state: Data<AppState>,
) -> HttpResponse {
    let db = &state.db;
    let result = form.forgot_password(&db).await;

    match result {
        Ok(()) => HttpResponse::Ok().json("password reset key sent to your email".to_string()),
        Err(err) => {
            eprintln!("Database error: {:?}", err);
            HttpResponse::InternalServerError().json("Internal Server Error")
        }
    }
}

pub async fn reset_password_handler(
    form: web::Json<ResetPassword>,
    state: Data<AppState>,
) -> HttpResponse {
    let db = &state.db;
    let result = form.reset_password(&db).await;

    match result {
        Ok(()) => HttpResponse::Ok().json("password reset successful".to_string()),
        Err(err) => {
            eprintln!("Database error: {:?}", err);
            HttpResponse::InternalServerError().json("Internal Server Error")
        }
    }
}
pub async fn create_user_profile_handler(
    form: web::Json<NewUserProfile>,
    path: web::Path<(i32,)>,
    state: Data<AppState>,
) -> HttpResponse {
    let db = &state.db;
    let result = form.create_user_profile(path, &db).await;

    match result {
        Ok(()) => HttpResponse::Ok().json("user profile created succesfully".to_string()),
        Err(err) => {
            eprintln!("Database error: {:?}", err);
            HttpResponse::InternalServerError().json("Internal Server Error")
        }
    }
}
pub async fn create_user_plan_handler(
    form: web::Json<NewUserPlan>,
    path: web::Path<i32>,
    state: Data<AppState>,
) -> HttpResponse {
    let db = &state.db;
    let result = form.create_user_plan(*path, &db).await;

    match result {
        Ok(()) => HttpResponse::Ok().json("user plan created succesfully".to_string()),
        Err(err) => {
            eprintln!("Database error: {:?}", err);
            HttpResponse::InternalServerError().json("Internal Server Error")
        }
    }
}

pub async fn fetch_exercises_handler(
    path: web::Path<(i32,)>,
    state: Data<AppState>,
) -> HttpResponse {
    let db = &state.db;

    match Exercises::fetch_exercises(path, db).await {
        Ok(x) => HttpResponse::Ok().json(x),
        Err(err_msg) => {
            println!("error : {:?}", err_msg);
            HttpResponse::InternalServerError().json("failed to fetch users")
        }
    }
}

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .route("/", web::get().to(fetch_users_handler))
            .route("/", web::post().to(create_user_handler))
            .route("/login", web::post().to(login_handler))
            .route("/forgot-password", web::post().to(forgot_password_handler))
            .route("/reset-password", web::post().to(reset_password_handler))
            .route(
                "/create-user-profile/{id}",
                web::post().to(create_user_profile_handler),
            )
            .route(
                "/create-user-plan/{id}",
                web::post().to(create_user_plan_handler),
            )
            .route(
                "/fetch-exercise/{id}",
                web::get().to(fetch_exercises_handler),
            ),
    );
}
