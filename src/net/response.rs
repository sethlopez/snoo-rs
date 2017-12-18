use std::sync::Arc;
use std::time::Instant;

use futures::prelude::*;
use futures::stream::Concat2;
use hyper::{self, Body, Chunk, Headers, StatusCode};
use hyper::client::FutureResponse;

use error::SnooError;
use reddit::RedditClient;

#[must_use = "futures do nothing unless polled"]
#[derive(Debug)]
pub struct HttpResponseFuture {
    response_future: Option<FutureResponse>,
    status: Option<StatusCode>,
    headers: Option<Headers>,
    body_future: Option<Concat2<Body>>,
}

impl HttpResponseFuture {
    pub fn new(response_future: FutureResponse) -> HttpResponseFuture {
        HttpResponseFuture {
            response_future: Some(response_future),
            status: None,
            headers: None,
            body_future: None,
        }
    }
}

impl Future for HttpResponseFuture {
    type Item = (Instant, StatusCode, Headers, Chunk);
    type Error = hyper::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // if there's a response future, poll it and set the status, header, and body fields
        if let Some(mut response_future) = self.response_future.take() {
            match response_future.poll() {
                Err(error) => return Err(error),
                Ok(Async::NotReady) => {
                    self.response_future = Some(response_future);
                    return Ok(Async::NotReady);
                }
                Ok(Async::Ready(response)) => {
                    self.status = Some(response.status());
                    self.headers = Some(response.headers().clone());
                    self.body_future = Some(response.body().concat2());
                }
            }
        }

        // if there's a body future, concatenate it into a chunk and return everything
        if let Some(mut body_future) = self.body_future.take() {
            match body_future.poll() {
                Err(error) => return Err(error),
                Ok(Async::NotReady) => {
                    self.body_future = Some(body_future);
                    return Ok(Async::NotReady);
                }
                Ok(Async::Ready(body)) => {
                    return Ok(Async::Ready((
                        Instant::now(),
                        self.status.take().unwrap(),
                        self.headers.take().unwrap(),
                        body,
                    )));
                }
            }
        }

        panic!("future has already completed")
    }
}

#[must_use = "futures do nothing unless polled"]
pub struct SnooFuture<T> {
    client: Arc<RedditClient>,
    error: Option<SnooError>,
    future: Option<Box<Future<Item = T, Error = SnooError>>>,
}
