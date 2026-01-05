use rocket::http::Method;
use rocket::request::{FromRequest, Outcome, Request};
use rocket_governor::{Quota, RocketGovernable};
use rocket_okapi::request::{OpenApiFromRequest, RequestHeaderInput};
use rocket_okapi::gen::OpenApiGenerator;

/// Rate limit guard for general API usage (Moderate limit)
#[derive(Debug, Clone, Copy)]
pub struct RateLimitGuard;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RateLimitGuard {
    type Error = String;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if request.client_ip().is_none() {
             return Outcome::Success(RateLimitGuard);
        }
        match rocket_governor::RocketGovernor::<'r, RateLimitConfig>::from_request(request).await {
            Outcome::Success(_) => Outcome::Success(RateLimitGuard),
            Outcome::Error((status, e)) => Outcome::Error((status, format!("Rate limit error: {:?}", e))),
            Outcome::Forward(f) => Outcome::Forward(f),
        }
    }
}

impl<'r> OpenApiFromRequest<'r> for RateLimitGuard {
    fn from_request_input(_gen: &mut OpenApiGenerator, _name: String, _required: bool) -> rocket_okapi::Result<RequestHeaderInput> {
        Ok(RequestHeaderInput::None)
    }
}

pub struct RateLimitConfig;

impl<'r> RocketGovernable<'r> for RateLimitConfig {
    fn quota(_method: Method, _route_name: &str) -> Quota {
        // 120 requests per minute per IP
        Quota::per_minute(std::num::NonZeroU32::new(120).expect("Rate limit quota must be non-zero"))
    }
}

/// Strict rate limit for login endpoints (Brute force protection)
#[derive(Debug, Clone, Copy)]
pub struct AuthRateLimitGuard;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthRateLimitGuard {
    type Error = String;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if request.client_ip().is_none() {
             return Outcome::Success(AuthRateLimitGuard);
        }
        match rocket_governor::RocketGovernor::<'r, AuthRateLimitConfig>::from_request(request).await {
            Outcome::Success(_) => Outcome::Success(AuthRateLimitGuard),
            Outcome::Error((status, e)) => Outcome::Error((status, format!("Rate limit error: {:?}", e))),
            Outcome::Forward(f) => Outcome::Forward(f),
        }
    }
}

impl<'r> OpenApiFromRequest<'r> for AuthRateLimitGuard {
    fn from_request_input(_gen: &mut OpenApiGenerator, _name: String, _required: bool) -> rocket_okapi::Result<RequestHeaderInput> {
        Ok(RequestHeaderInput::None)
    }
}

pub struct AuthRateLimitConfig;

impl<'r> RocketGovernable<'r> for AuthRateLimitConfig {
    fn quota(_method: Method, _route_name: &str) -> Quota {
        // 5 requests per minute per IP for login
        Quota::per_minute(std::num::NonZeroU32::new(5).expect("Auth rate limit quota must be non-zero"))
    }
}
