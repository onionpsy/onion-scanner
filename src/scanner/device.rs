use pnet::datalink::{MacAddr};
use std::net::{Ipv4Addr};
use colored::*;

pub struct Device {
    pub name: String,
    pub index: u16,
    pub ip: Ipv4Addr,
    pub mac: MacAddr
}

impl Device {
    pub fn summarize(&self) -> String {
        let name = &self.name[..self.name.chars().map(|c| c.len_utf8()).take(10).sum()];
        format!(" {: <2}  {: <12}  {}  {: <15}  aaaa",
            self.index.to_string().color("cyan"),
            name,
            self.mac.to_string().color("green"),
            self.ip.to_string().color("green")
        )
    }
}