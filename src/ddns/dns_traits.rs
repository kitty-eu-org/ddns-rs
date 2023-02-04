pub trait DnsUpdate {
    fn update_record(&mut self, domain: &str, dns_type: Option<&str>) -> ();
}