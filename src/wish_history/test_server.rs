//! A tiny in-process HTTP/1.1 server for the sync tests: one thread, one
//! request per connection, every request recorded.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

/// One request as the server saw it.
#[derive(Clone, Debug)]
pub(crate) struct Request {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) query: Vec<(String, String)>,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: String,
}

impl Request {
    pub(crate) fn param(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The whole request as text, for "the key is nowhere in it" checks.
    pub(crate) fn raw(&self) -> String {
        format!(
            "{} {} {:?} {:?} {}",
            self.method, self.path, self.query, self.headers, self.body
        )
    }
}

pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) body: String,
}

impl Reply {
    pub(crate) fn json(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
        }
    }
}

type Handler = Box<dyn FnMut(&Request) -> Reply + Send>;

pub(crate) struct TestServer {
    pub(crate) base: String,
    requests: Arc<Mutex<Vec<Request>>>,
}

impl TestServer {
    pub(crate) fn start(handler: impl FnMut(&Request) -> Reply + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        let base = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        let mut handler: Handler = Box::new(handler);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                serve(stream, &mut handler, &seen);
            }
        });
        Self { base, requests }
    }

    pub(crate) fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }
}

/// Read one request, record it, answer it. Recorded before the answer goes
/// out, so a client that has its answer always finds its request recorded.
fn serve(stream: TcpStream, handler: &mut Handler, seen: &Mutex<Vec<Request>>) -> Option<()> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_owned();
    let target = parts.next()?.to_owned();

    let mut headers = Vec::new();
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':')?;
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }
    let length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;

    let url = reqwest::Url::parse(&format!("http://test{target}")).ok()?;
    let request = Request {
        method,
        path: url.path().to_owned(),
        query: url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect(),
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    };
    let reply = handler(&request);
    seen.lock().unwrap().push(request);
    let mut stream = stream;
    let _ = write!(
        stream,
        "HTTP/1.1 {} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        reply.status,
        reply.body.len(),
        reply.body
    );
    let _ = stream.flush();
    Some(())
}
