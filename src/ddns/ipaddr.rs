use local_ip_address::{self, list_afinet_netifas};
use std::net::{IpAddr, UdpSocket};

#[derive(Clone, Debug)]
pub struct Ipv4DDNS {
    ip: String,
}
#[derive(Clone, Debug)]
pub struct Ipv6DDNS {
    ip: String,
}

pub enum Method {
    POST,
    GET,
    PUT,
}

pub enum IPAddr {
    IPV4,
    IPV6,
}

pub trait IpOprator {
    fn get_local_ip() -> String;
    fn get_internet_ip() -> String;
    fn get_addr(&self) -> String;
}

impl Ipv4DDNS {
    pub fn new() -> Ipv4DDNS {
        let local_ip = Self::get_local_ip();
        let net_ip = Self::get_internet_ip();
        let local_ip = if local_ip.eq(&net_ip) {
            local_ip
        } else {
            panic!(
                "local ipv4 is: {}, net ipv4 is: {}, check not pass!",
                local_ip, net_ip
            )
        };
        Self { ip: local_ip }
    }
}

impl Ipv6DDNS {
    pub fn new() -> Ipv6DDNS {
        let local_ip = Self::get_local_ip();
        let net_ip = Self::get_internet_ip();
        let local_ip = if local_ip.eq(&net_ip) {
            local_ip
        } else {
            panic!(
                "local ipv4 is: {}, net ipv4 is: {}, check not pass!",
                local_ip, net_ip
            )
        };
        Self { ip: local_ip }
    }
}

impl IpOprator for Ipv4DDNS {
    fn get_internet_ip() -> String {
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.connect("8.8.8.8:80").unwrap();
        let addr = socket.local_addr().unwrap().ip().to_string();
        addr
        
    }
    fn get_local_ip() -> String {
        let my_local_ip = local_ip_address::local_ip().unwrap();
        my_local_ip.to_string()
    }
    fn get_addr(&self) -> String {
        return self.ip.clone();
    }
}

impl IpOprator for Ipv6DDNS {
    fn get_internet_ip() -> String {
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.connect("8.8.8.8:80").unwrap();
        let addr = socket.local_addr().unwrap().ip().to_string();
        addr
    }
    fn get_local_ip() -> String {
        let ifas = list_afinet_netifas().unwrap();

        let ip = if let Some((_, ipaddr)) = ifas
            .iter()
            .find(|(name, ipaddr)| *name == "en0" && matches!(ipaddr, IpAddr::V6(_)))
        {
            ipaddr.to_owned().to_string()
        } else {
            panic!("get local ipv6 address error");
        };
        ip
    }

    fn get_addr(&self) -> String {
        return self.ip.clone();
    }
}


#[derive(Clone, Debug)]
pub enum DDNSIP {
    Ipv4(Ipv4DDNS),
    Ipv6(Ipv6DDNS),
}

impl DDNSIP {
    pub fn get_addr(&self) -> String {
        match self {
            DDNSIP::Ipv4(x) => x.get_addr(),
            DDNSIP::Ipv6(x) => x.get_addr(),
        }
    }
}
