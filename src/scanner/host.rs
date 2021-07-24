use pnet::datalink::{NetworkInterface};
use ipnet::{Ipv4Net};
use std::net::{IpAddr};

pub struct Host {
    pub interface: NetworkInterface
}

impl Host {
    pub fn ip(&self) -> Ipv4Net {
        match self.interface.ips[0].ip() {
            IpAddr::V4(ip4) => Ipv4Net::new(ip4, 24),
            IpAddr::V6(_) => unimplemented!()
        }.unwrap()
    }
}