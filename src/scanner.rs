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

    let (thread_tx, thread_rx) = mpsc::channel();
    scan(&mut *tx, &host, &thread_tx);

    let _ = read_and_display(&mut *rx, &mut *tx, host, &thread_rx);

    println!("Scan finished");
}

pub fn scan(tx: &mut dyn DataLinkSender, host: &Host, thread_tx: &mpsc::Sender<Result<()>>) {
    let _ = network::send_arp_packet(&mut *tx, &host.interface, &Ipv4Addr::new(172, 22, 22, 52));
    return;


    for ip in host.ip().hosts() {
        if ip == host.ip().addr() { continue; }
        let _ = network::send_arp_packet(&mut *tx, &host.interface, &ip);
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

    let mut devices: HashMap<MacAddr, device::Device> = HashMap::new();

    loop {
        match network::read_packets(&mut *rx) {
            Some(received_packet) => {
                let device = received_packet.handle(&host);
                match device {
                    Some(mut device) => {
                        let mac = &device.mac;
                        if devices.contains_key(mac) {
                            if !device.os.is_none() {
                                &devices.insert(device.mac, device);
                            }
                            
                        } else {
                            if !device.tcp_sent {
                                println!("send to {}", device.ip);
                                let _ = network::send_tcp_packet(tx, &host, &device);
                                device.tcp_sent = true;
                            }


                            &devices.insert(device.mac, device);
                        }
                    },
                    _ => ()
                };

            },
            _ => ()
        }
        
        match thread_rx.try_recv() {
            Ok(_) => return Ok(()),
            _ => {}
        }
    }
}