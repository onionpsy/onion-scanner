    use pnet::datalink::{MacAddr};
use std::net::{Ipv4Addr};
use colored::*;

#[derive(Debug)]
pub struct Device {
    pub name: String,
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
    pub os: Option<String>,
    pub tcp_sent: bool
}

impl Device {
    pub fn summarize(&self) -> String {
        let name = &self.name[..self.name.chars().map(|c| c.len_utf8()).take(10).sum()];
        format!(" {: <12}  {}  {: <15}  {: <20}",
            name,
            self.mac.to_string().color("green"),
            self.ip.to_string().color("green"),
            match &self.os {
                Some(os) => { os.color("cyan") },
                None => "".color("cyan")
            }
        )
    }
}