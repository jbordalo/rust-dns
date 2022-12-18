use bytes::{Buf, BufMut, Bytes, BytesMut};
use rand::Rng;
use core::fmt;
use std::{str, net::Ipv4Addr};

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
        write!(f, "\tName: {}\n\tQuery Type: {}\n\tClass: {}", self.name, self.query_type, self.class)
    }
}

struct Answer {
    name: String,
    query_type: u16,
    class: u16,
    ttl: u32,
    data_length: u16,
    address: u32,
}

impl fmt::Display for Answer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let addr = Ipv4Addr::from(self.address).to_string();
        write!(f, "\tName: {}\n\tQuery Type: {}\n\tClass: {}\n\tTTL: {}\n\tData Length: {}\n\tAddress: {}", self.name, self.query_type, self.class, self.ttl, self.data_length, addr)
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

        write!(f,
            "Id: {:x}
Flags: {:x}
Questions: {}
Answer RRs: {}
Authority RRs: {}
Additional RRs: {}
Queries:\n{}
Answers:\n{}
",
            self.id, self.flags, self.questions, self.answer_rr, self.auth_rr, self.add_rr, query, answer
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
        let answer = Answer { name, query_type: response.get_u16(), class: response.get_u16(), ttl: response.get_u32(), data_length: response.get_u16(), address: response.get_u32() };
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

pub fn build_dns_request(name: String) -> Bytes {
    let mut request = BytesMut::new();

    // Id
    request.put_u16(rand::thread_rng().gen());
    // Flags
    request.put_u16(0x0120);
    // Query Count
    request.put_u16(0x1);
    // Answer RRs
    request.put_u16(0);
    // Authority RRs
    request.put_u16(0);
    // Additional RRs
    request.put_u16(0);

    request = encode_name(name, request);

    // Query type
    request.put_u16(0x1);
    // Query class
    request.put_u16(0x1);

    request.freeze()
}
