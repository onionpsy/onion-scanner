mod network;
mod device;
mod fingerprint;
pub mod host;
mod received_packet;

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
use pnet::util::MacAddr;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption, TcpPacket};
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use std::collections::HashMap;

use host::{Host};

pub struct ScanningResult {
    pub devices: Vec<device::Device>
}

pub fn run(host: &Host) {
    
    let mut config = Config::default();
    config.read_timeout = Some(Duration::from_millis(200));
    config.write_timeout = Some(Duration::from_secs(3));
    let (mut tx, mut rx) = match pnet::datalink::channel(&host.interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Invalid channel"),
        Err(e) => panic!("Error {}", e)
    };

    println!("Scanning network {}/{}",
        host.ip().network().to_string().color("red"),
        host.ip().prefix_len().to_string().color("red")
    );


    /*let test = device::Device {
        index: 1,
        name: String::from(","),
        ip: Ipv4Addr::new(172, 22, 22, 1),
        mac: MacAddr::new(0x98, 0x9d, 0x5d, 0xbe, 0xcc, 0x78)
    };

    let _ = fingerprint::detect_os(&mut *tx, host, &test.ip, &test.mac);*/

    let (thread_tx, thread_rx) = mpsc::channel();

    scan(&mut *tx, &host, &thread_tx);

    let _ = read_and_display(&mut *rx, &mut *tx, host, &thread_rx);

    println!("Scan finished");
}

pub fn scan(tx: &mut dyn DataLinkSender, host: &Host, thread_tx: &mpsc::Sender<Result<()>>) {
    /*let _ = crossbeam::scope(|scope| {
        scope.spawn(move |_| {
            for ip in host.ip().hosts() {
                let _ = scan_ip(&mut *tx, &host.interface, ip);
                thread::sleep(Duration::from_millis(200));
            }
            let _ = thread_tx.send(Ok(()));
        });
    });*/
    for ip in host.ip().hosts() {
        let _ = scan_ip(&mut *tx, &host.interface, ip);
        //thread::sleep(Duration::from_millis(200));
    }
    //let _ = thread_tx.send(Ok(()));
}

pub fn read_and_display(
    rx: &mut dyn DataLinkReceiver,
    tx: &mut dyn DataLinkSender,
    host: &Host,
    thread_rx: &mpsc::Receiver<Result<()>>
) -> Result<()> {

    let devices: HashMap<&MacAddr, &device::Device> = HashMap::new();

    loop {
        match network::read_packets(&mut *rx) {
            Some(received_packet) => {
                let device = received_packet.handle(&devices, &host);
                match device {
                    Some(device) => {
                        let _ = fingerprint::detect_os(&mut *tx, host, &device.ip, &device.mac);
                        println!("{}", device.summarize());
                        std::process::exit(0);
                    },
                    _ => {}
                };

            },
            _ => {}
        }
        
        match thread_rx.try_recv() {
            Ok(_) => return Ok(()),
            _ => {}
        }
    }
}


pub fn scan_ip(tx: &mut dyn DataLinkSender, interface: &NetworkInterface, target_ip: Ipv4Addr) -> Result<()> {
    network::send_arp_packet(&mut *tx, interface, &target_ip)
}