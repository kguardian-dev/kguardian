use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};
use futures_util::future::LocalBoxFuture;
use std::{
    env,
    future::{ready, Ready},
    rc::Rc,
};
use tracing::warn;

pub struct ApiKeyAuth;

impl<S, B> Transform<S, ServiceRequest> for ApiKeyAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = ApiKeyAuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        let api_key = match env::var("API_KEY") {
            Ok(k) if !k.is_empty() => {
                Some(k)
            }
            _ => {
                warn!("API_KEY env var is not set; all requests will be allowed (set API_KEY to enable authentication)");
                None
            }
        };

        ready(Ok(ApiKeyAuthMiddleware {
            service: Rc::new(service),
            api_key,
        }))
    }
}

pub struct ApiKeyAuthMiddleware<S> {
    service: Rc<S>,
    api_key: Option<String>,
}

impl<S, B> Service<ServiceRequest> for ApiKeyAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // /health is exempt from auth
        if req.path() == "/health" {
            let svc = Rc::clone(&self.service);
            return Box::pin(async move {
                let res = svc.call(req).await?;
                Ok(res.map_into_left_body())
            });
        }

        let expected = match &self.api_key {
            None => {
                // No key configured — pass all requests through
                let svc = Rc::clone(&self.service);
                return Box::pin(async move {
                    let res = svc.call(req).await?;
                    Ok(res.map_into_left_body())
                });
            }
            Some(k) => k.clone(),
        };

        let provided = req
            .headers()
            .get("X-API-Key")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned());

        let authed = provided.as_deref() == Some(expected.as_str());

        if authed {
            let svc = Rc::clone(&self.service);
            Box::pin(async move {
                let res = svc.call(req).await?;
                Ok(res.map_into_left_body())
            })
        } else {
            Box::pin(async move {
                let (req, _payload) = req.into_parts();
                let response = HttpResponse::Unauthorized()
                    .content_type("application/json")
                    .body(r#"{"error":"Unauthorized: missing or invalid API key"}"#)
                    .map_into_right_body();
                Ok(ServiceResponse::new(req, response))
            })
        }
    }
}
