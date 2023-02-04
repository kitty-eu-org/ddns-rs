mod huawei_cloud;
mod ipaddr;
mod dns_traits;

pub use huawei_cloud::HuaWeiCloudDDNS;
pub use ipaddr::{IPAddr, Ipv4DDNS, Ipv6DDNS, Method, DDNSIP};
pub use dns_traits::DnsUpdate;
