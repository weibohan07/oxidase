mod ctx;
mod matcher;
mod ops;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{body, http};

use crate::build::service::LoadedRouter;
use crate::config::router::OnMatch;
use crate::handler::{BoxResponseFuture, ServiceHandler};
use crate::util::http::make_error_resp;

use ctx::{apply_ctx_to_request, RouterCtx};
use matcher::{matches_rule, MatchResult};
use ops::{run_ops, OpOutcome};

impl ServiceHandler for LoadedRouter {
    fn handle_request<'a>(
        &'a self,
        req: &'a mut http::Request<body::Incoming>,
    ) -> BoxResponseFuture<'a> {
        Box::pin(async move { route_request(self, req).await })
    }
}

async fn route_request(
    router: &LoadedRouter,
    req: &mut http::Request<body::Incoming>,
) -> http::Response<Full<Bytes>> {
    let mut ctx = RouterCtx::from_request(req);
    let mut step = 0u32;
    let mut idx = 0usize;

    loop {
        if step >= router.max_steps {
            return make_error_resp(http::StatusCode::LOOP_DETECTED, "router steps exceeded");
        }

        if idx >= router.rules.len() {
            if let Some(nx) = &router.next {
                apply_ctx_to_request(&ctx, req);
                return nx.handle_request(req).await;
            } else {
                return make_error_resp(http::StatusCode::NOT_FOUND, "no route matched");
            }
        }

        let rule = &router.rules[idx];

        match matches_rule(&rule.when, &mut ctx) {
            MatchResult::NoMatch => {
                idx += 1;
                continue;
            }
            MatchResult::Match => {}
        }

        match run_ops(&rule.ops, &mut ctx, req).await {
            OpOutcome::ContinueNextRule => {
                idx += 1;
            }
            OpOutcome::Restart => {
                step += 1;
                idx = 0;
            }
            OpOutcome::Respond(resp) => return resp,
            OpOutcome::UseService(resp) => return resp,
            OpOutcome::Fallthrough => {
                match rule.on_match {
                    OnMatch::Stop => {
                        if let Some(n) = &router.next {
                            apply_ctx_to_request(&ctx, req);
                            return n.handle_request(req).await;
                        } else {
                            return make_error_resp(http::StatusCode::NOT_FOUND, "no route matched");
                        }
                    }
                    OnMatch::Continue => idx += 1,
                    OnMatch::Restart => {
                        step += 1;
                        idx = 0;
                    }
                }
            }
        }
    }
}
