use bytes::{Buf, BufMut, Bytes, BytesMut};
use core::fmt;
use rand::Rng;
use std::{net::Ipv4Addr, str};

fn encode_name(name: String, mut response: BytesMut) -> BytesMut {
    let labels = name.split(".");

    for l in labels {
        response.put_u8(l.len().try_into().unwrap());
        response.put(l.as_bytes());
    }

    response.put_u8(0);

    response
}

pub struct Query {
    name: String,
    query_type: u16,
    class: u16,
}

impl Query {
    fn new(name: String, query_type: u16, class: u16) -> Self {
        Query {
            name,
            query_type,
            class,
        }
    }

    pub fn get_name(&self) -> String {
        self.name.clone()
    }
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\tName: {}\n\tQuery Type: {}\n\tClass: {}",
            self.name, self.query_type, self.class
        )
    }
}

struct Answer {
    name: String,
    query_type: u16,
    class: u16,
    ttl: u32,
    data_length: u16,
    address: Ipv4Addr,
}

impl fmt::Display for Answer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\tName: {}\n\tQuery Type: {}\n\tClass: {}\n\tTTL: {}\n\tData Length: {}\n\tAddress: {}", self.name, self.query_type, self.class, self.ttl, self.data_length, self.address)
    }
}

type DNSName = String;
pub struct DNSRequest {
    id: u16,
    name: DNSName,
    flags: u16,
    query_count: u16,
    answer_rr: u16,
    auth_rr: u16,
    add_rr: u16,
    queries: Vec<Query>,
}

impl DNSRequest {
    pub fn new(name: DNSName) -> Self {
        let query = Query::new(name.clone(), 0x1, 0x1);

        let queries = vec![query];

        DNSRequest {
            name,
            queries,
            ..Default::default()
        }
    }
}

impl fmt::Display for DNSRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let query = self.queries.get(0).unwrap();

        write!(
            f,
            "Id: {:x}
Name: {},
Flags: {:x}
Query Count: {}
Answer RRs: {}
Authority RRs: {}
Additional RRs: {}
Queries:\n{}
",
            self.id,
            self.name,
            self.flags,
            self.query_count,
            self.answer_rr,
            self.auth_rr,
            self.add_rr,
            query
        )
    }
}

impl From<DNSRequest> for Bytes {
    fn from(dns_request: DNSRequest) -> Self {
        let mut request = BytesMut::new();

        // Id
        request.put_u16(dns_request.id);
        // Flags
        request.put_u16(dns_request.flags);
        // Query Count
        request.put_u16(dns_request.query_count);
        // Answer RRs
        request.put_u16(dns_request.answer_rr);
        // Authority RRs
        request.put_u16(dns_request.auth_rr);
        // Additional RRs
        request.put_u16(dns_request.add_rr);

        request = encode_name(dns_request.name, request);

        // TODO add multiple queries
        let query = dns_request.queries.get(0).unwrap();

        // Query type
        request.put_u16(query.query_type);
        // Query class
        request.put_u16(query.class);

        request.freeze()
    }
}

impl Default for DNSRequest {
    fn default() -> Self {
        DNSRequest {
            id: rand::thread_rng().gen(),
            name: String::new(),
            flags: 0x0120,
            query_count: 0x1,
            answer_rr: 0,
            auth_rr: 0,
            add_rr: 0,
            queries: Vec::new(),
        }
    }
}

pub struct DNSResponse {
    id: u16,
    flags: u16,
    questions: u16,
    answer_rr: u16,
    auth_rr: u16,
    add_rr: u16,
    queries: Vec<Query>,
    answers: Vec<Answer>,
}

impl DNSResponse {
    fn new(id: u16, flags: u16, questions: u16, answer_rr: u16, auth_rr: u16, add_rr: u16) -> Self {
        DNSResponse {
            id,
            flags,
            questions,
            answer_rr,
            auth_rr,
            add_rr,
            queries: Vec::new(),
            answers: Vec::new(),
        }
    }

    fn add_query(&mut self, query: Query) {
        self.queries.push(query);
    }

    fn add_answer(&mut self, answer: Answer) {
        self.answers.push(answer);
    }
}

impl fmt::Display for DNSResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let answer = self.answers.get(0).unwrap();
        let query = self.queries.get(0).unwrap();

        write!(
            f,
            "Id: {:x}
Flags: {:x}
Questions: {}
Answer RRs: {}
Authority RRs: {}
Additional RRs: {}
Queries:\n{}
Answers:\n{}
",
            self.id,
            self.flags,
            self.questions,
            self.answer_rr,
            self.auth_rr,
            self.add_rr,
            query,
            answer
        )
    }
}

fn parse_queries(dns_response: &mut DNSResponse, response: &mut Bytes) {
    for _ in 0..dns_response.answer_rr {
        let mut labels: Vec<String> = Vec::new();
        let mut length = response.get_u8();
        while length != 0x00 {
            let offset = length.try_into().unwrap();
            let label = response.copy_to_bytes(offset);
            labels.push(str::from_utf8(&label.to_vec()).unwrap().to_string());
            length = response.get_u8();
        }
        let name = labels.join(".");
        let query_type = response.get_u16();
        let class = response.get_u16();

        let query = Query::new(name, query_type, class);
        dns_response.add_query(query);
    }
}

fn parse_answers(dns_response: &mut DNSResponse, response: &mut Bytes) {
    for _ in 0..dns_response.answer_rr {
        response.get_u16();
        let name = dns_response.queries.get(0).unwrap().get_name();
        let answer = Answer {
            name,
            query_type: response.get_u16(),
            class: response.get_u16(),
            ttl: response.get_u32(),
            data_length: response.get_u16(),
            address: Ipv4Addr::from(response.get_u32()),
        };
        dns_response.add_answer(answer);
    }
}

pub fn parse_response(mut response: Bytes) -> DNSResponse {
    let mut dns_response = DNSResponse::new(
        response.get_u16(),
        response.get_u16(),
        response.get_u16(),
        response.get_u16(),
        response.get_u16(),
        response.get_u16(),
    );

    parse_queries(&mut dns_response, &mut response);
    parse_answers(&mut dns_response, &mut response);

    dns_response
}
