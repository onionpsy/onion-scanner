extern crate pnet;

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
        eprintln!("{} {}\n", "error".to_string().color("red"), e);
        std::process::exit(0)
    });

    let interface = &interfaces
        .iter()
        .find(|i| i.index == config.interface_index);

    
    match interface {
        Some(interface) => {
            println!("Using interface {:?} {}.", &interface.name, &interface.ips[0]);
        },
        None => panic!("Error while finding the default interface."),
    }

    scanner::run(&interface.unwrap());
}