mod ddns;

use crate::ddns::DnsUpdate;
use crate::ddns::{HuaWeiCloudDDNS, IPAddr};

fn run<T: DnsUpdate>(dns: &mut T) -> () {
    let update_res = dns.update_record("hezhaozhao.top.", Some("A"));
    println!("update_res is : {:?}", update_res);
}
fn main() {
    let mut huawei_cloud = HuaWeiCloudDDNS::new(IPAddr::IPV4);
    run(&mut huawei_cloud);
}
