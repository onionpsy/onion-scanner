mod network;
mod device;

extern crate pnet;
extern crate ipnet;
extern crate colored;

use std::net::{Ipv4Addr, IpAddr};
use std::time::Duration;
use std::io::{Result};
use pnet::datalink::{DataLinkSender, DataLinkReceiver, Config, Channel, NetworkInterface};
use std::thread;
use ipnet::{Ipv4Net};
use colored::*;
use std::sync::mpsc;

pub struct ScanningResult {
    pub devices: Vec<device::Device>
}

pub fn run(interface: &NetworkInterface) {
    
    let mut config = Config::default();
    config.read_timeout = Some(Duration::from_millis(200));
    config.write_timeout = Some(Duration::from_secs(3));
    let (mut tx, mut rx) = match pnet::datalink::channel(&interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Invalid channel"),
        Err(e) => panic!("Error {}", e)
    };

    let host_ip = match interface.ips[0].ip() {
        IpAddr::V4(ip4) => Ipv4Net::new(ip4, 24),
        IpAddr::V6(_) => unimplemented!()
    }.unwrap();

    let i = interface.clone();

    println!("Scanning network {}/{}",
        host_ip.network().to_string().color("red"),
        host_ip.prefix_len().to_string().color("red")
    );

    let (thread_tx, thread_rx) = mpsc::channel();

    thread::spawn(move || {
        for ip in host_ip.hosts() {
            let _ = scan_ip(&mut *tx, ip, &i);
            thread::sleep(Duration::from_millis(200));
        }
        let _ = thread_tx.send(Ok(()));
    });

    let _ = read_and_display(&mut *rx, &thread_rx);

    println!("Scan finished");
}

pub fn read_and_display(rx: &mut dyn DataLinkReceiver, thread_rx: &mpsc::Receiver<Result<()>>) -> Result<()> {
    let mut result = ScanningResult {
        devices: Vec::new()
    };

    let mut index: u16 = 1;

    loop {
        match network::read_arp_packet(&mut *rx) {
            Ok(Some(arp)) => {
                let mac = arp.get_sender_hw_addr();
                match result.devices.iter().find(|d| d.mac == mac) {
                    Some(_) => {},
                    _ => {
                        let device = device::Device {
                            name: String::from("test"),
                            index: index,
                            ip: arp.get_sender_proto_addr(),
                            mac: arp.get_sender_hw_addr()
                        };
                        println!("{}", device.summarize());
                        result.devices.push(device);
                        index += 1
                    }
                }
            },
            _ => {}
        }
        
        match thread_rx.try_recv() {
            Ok(_) => return Ok(()),
            _ => {}
        }
    }
}

pub fn scan_ip(tx: &mut dyn DataLinkSender, target_ip: Ipv4Addr, interface: &NetworkInterface) -> Result<()> {
    network::send_arp_packet(&mut *tx, target_ip, interface)
}
