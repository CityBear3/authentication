use actix_identity::{CookieIdentityPolicy, Identity, IdentityService};
use actix_redis::RedisSession;
use actix_session::Session;
use actix_web::{
    dev, get, http,
    middleware::{
        errhandlers::{ErrorHandlerResponse, ErrorHandlers},
        Logger,
    },
    post, App, HttpResponse, HttpServer, Result,
};
//use auth_sample::model::User;
use bigint::U256;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use std::fs::File;

#[get("/")]
async fn index(ss: Session, id: Identity) -> Result<HttpResponse, actix_web::Error> {
    let session_key = ss.get::<String>("auth_token").unwrap();
    let secure_token = id.identity();
    if session_key == None || secure_token == None {
        Ok(HttpResponse::Ok().body("Welcome to this web site!"))
    } else {
        if session_key.unwrap() == secure_token.unwrap() {
            Ok(HttpResponse::Ok().body("Hello, User!"))
        } else {
            Ok(HttpResponse::Ok().body("Welcome to this web site!"))
        }
    }
}

#[get("/login")]
async fn login(session: Session, id: Identity) -> Result<HttpResponse, actix_web::Error> {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut data = [0u8; 32];
    rng.fill_bytes(&mut data);
    let num: U256 = U256::from(data);
    let val = num.to_string();
    id.remember(val.clone());
    session.renew();
    session.set("auth_token", val).unwrap();
    //session.set("counter", 0).unwrap();
    Ok(HttpResponse::Found().header("location", "/").finish())
}

#[get("logout")]
async fn logout(ss: Session, id: Identity) -> Result<HttpResponse, actix_web::Error> {
    ss.purge();
    id.forget();
    //Ok(HttpResponse::Found().header("location", "/").finish())
    Ok(HttpResponse::Ok().finish())
}

fn render_404<T>(mut res: dev::ServiceResponse<T>) -> Result<ErrorHandlerResponse<T>> {
    res.response_mut().headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("Error"),
    );
    Ok(ErrorHandlerResponse::Response(res))
}

#[actix_web::main]
async fn main() -> Result<(), actix_web::Error> {
    std::env::set_var("RUST_LOG", "info");
    simplelog::CombinedLogger::init(vec![
        simplelog::TermLogger::new(
            simplelog::LevelFilter::Info,
            simplelog::Config::default(),
            simplelog::TerminalMode::Mixed,
            simplelog::ColorChoice::Auto,
        ),
        simplelog::WriteLogger::new(
            simplelog::LevelFilter::Info,
            simplelog::Config::default(),
            File::create("warn.log").unwrap(),
        ),
    ])
    .unwrap();

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("localhost-key.pem", SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file("localhost.pem").unwrap();

    HttpServer::new(|| {
        App::new()
            .service(index)
            .service(login)
            .service(logout)
            .wrap(Logger::default())
            .wrap(ErrorHandlers::new().handler(http::StatusCode::NOT_FOUND, render_404))
            .wrap(
                RedisSession::new("127.0.0.1:6379", &[0; 32])
                    .ttl(60)
                    .cookie_same_site(actix_redis::SameSite::Strict)
                    .cookie_secure(true)
                    .cookie_http_only(true),
            )
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(&[0; 32])
                    .name("secure_token")
                    .secure(true)
                    .same_site(actix_redis::SameSite::Strict)
                    .http_only(true),
            ))
    })
    .bind_openssl("localhost:8080", builder)?
    .run()
    .await?;

    Ok(())
}
