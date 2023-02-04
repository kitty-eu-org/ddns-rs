use super::{IPAddr, Ipv4DDNS, Ipv6DDNS, Method, DDNSIP};
use super::DnsUpdate;
use chrono::offset::Utc;
use hmac::{Hmac, Mac};
use reqwest::header::HeaderMap;
use serde_json::json;
use serde_json::value::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::time::Duration;
use url::Url;

#[derive(Clone, Debug)]
struct Rescord {
    id: String,
    _dns_type: String,
    _name: String,
    records: Vec<String>,
    _ttl: i64,
}

pub struct HuaWeiCloudDDNS {
    api_base_url: Url,
    ddns: DDNSIP,
    records: HashMap<String, Vec<Rescord>>,
}

impl HuaWeiCloudDDNS {
    pub fn new(ip_flag: IPAddr) -> Self {
        let api_base_url: &'static str = "https://dns.myhuaweicloud.com";
        let url = Url::parse(api_base_url).unwrap();
        let ddns = match ip_flag {
            IPAddr::IPV4 => DDNSIP::Ipv4(Ipv4DDNS::new()),
            IPAddr::IPV6 => DDNSIP::Ipv6(Ipv6DDNS::new()),
        };
        // let ipv4_ddns = Ipv4DDNS::new();
        let records = HashMap::new();
        Self {
            api_base_url: url,
            ddns: ddns,
            records: records,
        }
    }

    fn sha256_encode(data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        format!("{:X}", hasher.finalize()).to_lowercase()
    }

    fn hmac_signature(key: &str, msg: &str) -> String {
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
        mac.update(&msg.as_bytes());

        let hex_string = hex::encode(mac.finalize().into_bytes());

        hex_string
    }

    fn generate_headers(&self) -> (HashMap<String, String>, Vec<String>) {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        headers.insert(
            "X-Sdk-Date".to_owned(),
            // "20230201T045631Z".to_owned(),
            Utc::now().format("%Y%m%dT%H%M%SZ").to_string().to_owned(),
        );
        headers.insert(
            "host".to_owned(),
            self.api_base_url.domain().unwrap().to_owned(),
        );
        let mut sign_headers: Vec<String> = Vec::new();
        for key in headers.keys() {
            sign_headers.push(key.to_lowercase());
        }
        sign_headers.sort();
        (headers, sign_headers)
    }

    fn canonical_headers(
        &self,
        headers: &HashMap<String, String>,
        sign_headers: &Vec<String>,
    ) -> String {
        let mut a: Vec<String> = Vec::new();
        let mut lower_headers: HashMap<String, String> = HashMap::new();
        for (key, value) in headers {
            lower_headers.insert(key.to_lowercase(), value.trim().to_string());
        }
        for key in sign_headers {
            a.push(format!("{}:{}", key, lower_headers.get(key).unwrap()))
        }
        a.join("\n") + "\n"
    }

    fn request(
        &self,
        method: Method,
        path: &str,
        param: Option<Vec<(String, String)>>,
        body: Option<String>,
    ) -> HashMap<String, Value> {
        let (mut headers, sign_headers) = self.generate_headers();
        let body = body.unwrap_or(String::from(""));
        let hex_encode = Self::sha256_encode(&body);
        let canonical_headers = self.canonical_headers(&headers, &sign_headers);
        let sign_path = if !path.ends_with("/") {
            format!("{}/", path)
        } else {
            path.to_owned()
        };
        let query_string = serde_urlencoded::to_string(&param).unwrap();

        let method_value = match method {
            Method::POST => "POST",
            Method::PUT => "PUT",
            Method::GET => "GET",
        };
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method_value,
            sign_path,
            query_string,
            canonical_headers,
            sign_headers.join(";"),
            hex_encode
        );
        let hashed_canonical_request = Self::sha256_encode(&canonical_request);
        let str_to_sign = format!(
            "{}\n{}\n{}",
            "SDK-HMAC-SHA256",
            headers.get("X-Sdk-Date").unwrap(),
            hashed_canonical_request
        );

        let secret = env::var("DDNS_TOKEN").unwrap();
        let app_id = env::var("DDNS_ID").unwrap();

        let signature = Self::hmac_signature(&secret, &str_to_sign);

        let auth_header = format!(
            "{} Access={}, SignedHeaders={}, Signature={}",
            "SDK-HMAC-SHA256",
            &app_id,
            sign_headers.join(";"),
            signature
        );
        headers.insert("Authorization".to_owned(), auth_header);

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Client::new()");
        let url = self.api_base_url.join(&path).unwrap();

        let query: Vec<(String, String)> = param.unwrap_or(Vec::new());

        let last_headers = HeaderMap::try_from(&headers).unwrap();
        let response = match method {
            Method::POST => client
                .post(url)
                .headers(last_headers)
                .body(body)
                .query(&query)
                .send()
                .unwrap(),
            Method::GET => client
                .get(url)
                .headers(last_headers)
                .query(&query)
                .send()
                .unwrap(),
            Method::PUT => client
                .put(url)
                .headers(last_headers)
                .query(&query)
                .body(body)
                .send()
                .unwrap(),
        };

        let status_code = response.status().as_u16();
        let response1 = match status_code {
            status_code if status_code >= 200 && status_code < 300 => {
                response.json::<HashMap<String, Value>>().unwrap()
            }
            _ => {
                let data = response.text().unwrap();
                panic!(
                    "{}",
                    format!("{:?} : error {:?}: {:?}", path, status_code, data)
                );
            }
        };
        response1
    }

    fn get_zone_id(&self, domain: &str) -> Option<String> {
        let resp = self.request(Method::GET, "/v2/zones", None, None);
        let zones = resp.get("zones").unwrap().as_array().unwrap().to_owned();
        let ids: Vec<String> = zones
            .iter()
            .filter(|x| x.get("name").unwrap().as_str().unwrap().ends_with(domain))
            .map(|x| x.get("id").unwrap().as_str().unwrap().to_string())
            .collect();
        match ids.get(0) {
            Some(x) => Some(x.to_owned()),
            None => None,
        }
    }

    fn get_records(&mut self, zone_id: &str, domain: &str, dns_type: &str) -> Vec<Rescord> {
        let domain = if domain.ends_with(".") {domain.to_string()} else {domain.to_string() + "."};
        let key = format!("{}_{}_{}", zone_id, domain, dns_type);
        if self.records.contains_key(&key) {
            return self.records[&key].clone();
        }
        let query_params: Vec<(String, String)> = Vec::from([
            ("name".to_string(), domain.to_string()),
            ("type".to_string(), dns_type.to_string()),
        ]);
        let resp = self.request(
            Method::GET,
            format!("/v2/zones/{}/recordsets", zone_id).as_str(),
            Some(query_params),
            None,
        );
        let recordsets = resp["recordsets"].as_array().unwrap().to_owned();
        let mut records = Vec::new();
        for item in recordsets {
            let name = item["name"].as_str().to_owned().unwrap().to_string();
            if name != domain {
                continue
            }
            let record = Rescord {
                id: item["id"].as_str().to_owned().unwrap().to_string(),
                _dns_type: item["type"].as_str().to_owned().unwrap().to_string(),
                _name: item["name"].as_str().to_owned().unwrap().to_string(),
                records: item["records"]
                    .as_array()
                    .unwrap()
                    .to_owned()
                    .iter()
                    .map(|x| x.as_str().to_owned().unwrap().to_string())
                    .collect(),
                _ttl: item["ttl"].as_i64().unwrap(),
            };
            records.push(record);
        }
        self.records.insert(key.clone(), records);
        self.records[&key].clone()
    }

    // pub fn update_record(&mut self, domain: &str, dns_type: Option<&str>) -> () {
        
    // }
}

impl DnsUpdate for HuaWeiCloudDDNS {
    fn update_record(&mut self, domain: &str, dns_type: Option<&str>) -> () {
        let dns_type = dns_type.unwrap_or("A");
        let zone_id = self.get_zone_id(domain).unwrap();
        let records = self.get_records(&zone_id, domain, dns_type);
        let ip_addr = self.ddns.get_addr();
        if records.len() > 0 {
            for record in records {
                if record.records != vec![ip_addr.clone()] {
                    let body = json!({
                        "name": domain,
                        "type": dns_type,
                        "ttl": 50,
                        "records": [ip_addr]
                    });
                    let resp = self.request(
                        Method::PUT,
                        format!("/v2/zones/{}/recordsets/{}", zone_id, record.id).as_str(),
                        None,
                        Some(body.to_string()),
                    );
                    let domain = resp.get("name").unwrap().as_str().unwrap();
                    let status = resp.get("status").unwrap().as_str().unwrap();
                    let update_records: Vec<String> = resp
                        .get("records")
                        .unwrap()
                        .as_array()
                        .unwrap()
                        .to_owned()
                        .iter()
                        .map(|x| x.as_str().unwrap().to_string())
                        .collect();
                    println!(
                        "update dns success: domain: {}, status: {}, records: {:?}!",
                        domain, status, update_records
                    );
                }
            }
        } else {
            let body = json!({
                "name": domain,
                "type": dns_type,
                "ttl": 50,
                "records": [ip_addr]
            });
            let resp = self.request(
                Method::POST,
                format!("/v2/zones/{}/recordsets", zone_id).as_str(),
                None,
                Some(body.to_string()),
            );

            let domain = resp.get("name").unwrap().as_str().unwrap();
            let status = resp.get("status").unwrap().as_str().unwrap();
            let create_records: Vec<String> = resp
                .get("records")
                .unwrap()
                .as_array()
                .unwrap()
                .to_owned()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect();
            println!(
                "create dns success: domain: {}, status: {}, records: {:?}!",
                domain, status, create_records
            );
        }
        ()
    }
}

#[test]
fn feature() {
    let mut huawei_cloud = HuaWeiCloudDDNS::new(IPAddr::IPV4);

    let zone_id = huawei_cloud.get_zone_id("hezhaozhao.top").unwrap();
    let records = huawei_cloud.get_records(&zone_id, "hezhaozhao.top", "A");
    let update_res = huawei_cloud.update_record("hezhaozhao.top", Some("A"));
    println!("zone_id is : {}", zone_id);
    println!("records is : {:?}", records);
    println!("update_res is : {:?}", update_res);
}
