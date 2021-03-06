extern crate pnet;

#[macro_use]
extern crate lazy_static;

use pnet::{datalink};
use colored::*;

pub mod config;
pub mod scanner;


fn main() {
    let interfaces = datalink::interfaces();
    let interface_indexes = interfaces
        .iter()
        .filter(|i| {
            !i.is_loopback()
                && !i.ips.is_empty()
                && !i.ips[0].ip().is_multicast()
                && !i.ips[0].ip().is_unspecified()
        })
        .map(|i| i.index)
        .collect::<Vec<u32>>();

    let config = config::Config::parse(&interface_indexes).unwrap_or_else(|e| {
        panic!("{} {}\n", "error".to_string().color("red"), e);
    });

    let interface = interfaces
        .into_iter()
        .find(|i| i.index == config.interface_index)
        .unwrap();

    let host = scanner::host::Host {
        interface: interface
    };


    scanner::run(&host, config.timeout);
}
