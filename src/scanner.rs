mod network;
mod device;
mod fingerprint;
pub mod host;
mod received_packet;

extern crate pnet;
extern crate ipnet;
extern crate colored;

use std::io::{Result};
use pnet::datalink::{DataLinkSender, DataLinkReceiver, Config, Channel};
use std::thread;
use colored::*;
use pnet::util::MacAddr;
use std::collections::HashMap;
use received_packet::{ ReceivedPacket, ReceivedPacketTrait};
use std::time::{Duration, SystemTime};

use host::{Host};

pub fn run(host: &Host, timeout: u32) {
    let mut config = Config::default();
    config.read_timeout = Some(Duration::from_millis(200));
    config.write_timeout = Some(Duration::from_secs(3));
    let (mut tx, mut rx) = match pnet::datalink::channel(&host.interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Invalid channel"),
        Err(e) => panic!("Error {}", e)
    };

    println!("Scanning network {}/{}\r\n",
        host.ip().network().to_string().color("red"),
        host.ip().prefix_len().to_string().color("red")
    );

    scan(&mut *tx, &host);

    let _ = read_and_display(&mut *rx, &mut *tx, host, timeout);
    println!("Scan finished");
}

pub fn scan(tx: &mut dyn DataLinkSender, host: &Host) {
    for ip in host.ip().hosts() {
        if ip == host.ip().addr() { continue; }
        let _ = network::send_arp_packet(&mut *tx, &host.interface, &ip);
        thread::sleep(Duration::from_millis(20));
    }
}

pub fn read_and_display(
    rx: &mut dyn DataLinkReceiver,
    tx: &mut dyn DataLinkSender,
    host: &Host,
    timeout: u32
) -> Result<()> {

    let mut devices: HashMap<MacAddr, device::Device> = HashMap::new();

    let now = SystemTime::now();

    loop {
        if let Ok(frame) = rx.next() {
            match network::read_packets(&frame) {
                Some(ReceivedPacket::Arp(packet)) => {
                    let device = packet.handle(&host);
                    match device {
                        Some(device) => {
                            if !devices.contains_key(&device.mac) {
                                let _ = network::send_tcp_packet(tx, host, &device);
                                devices.insert(device.mac, device);
                            }
                        },
                        None => {}
                    }
                },
                Some(ReceivedPacket::TcpIp(packet)) => {
                    let device = packet.handle(&host);
                    match device {
                        Some(device) => {
                            let mac = device.mac;
                            if (!devices.contains_key(&mac) || devices[&mac].os.is_none()) && device.os.is_some() {
                                devices.insert(device.mac, device);
                                println!("{}", devices[&mac].summarize());
                            }

                        },
                        None => {}
                    }
                },
                None => {}
            };
        }


        // Stop scan after a certain amount of time
        if now.elapsed().expect("Error fetching system time") > Duration::from_secs(u64::from(timeout)) {
            break;
        }
    }

    Ok(())
}