
use crate::scanner::host::{Host};
use crate::scanner::device::Device;
use crate::scanner::fingerprint;

use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption, TcpPacket};
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use std::net::{Ipv4Addr, IpAddr};
use std::collections::HashMap;
use pnet::util::MacAddr;
use std::io::Result;
use ipnet::{Ipv4Net};
use pnet::packet::ethernet::{EthernetPacket};
use crate::pnet::packet::Packet;


pub enum ReceivedPacket<'a, 'b> {
    Arp(EthernetPacket<'a>),
    Tcp(EthernetPacket<'b>)
}


impl ReceivedPacket<'_, '_> {
    pub fn handle(&self, host: &Host) -> Option<Device> {
        match &*self {
            ReceivedPacket::Arp(arp) => self.handle_arp_packet(&arp, &host),
            ReceivedPacket::Tcp(tcp) => self.handle_tcp_packet(&tcp, &host),
        }
    }

    fn handle_arp_packet(&self, eth: &EthernetPacket, host: &Host) -> Option<Device> {
        let mac = &eth.get_source();
        if mac == &host.interface.mac.unwrap() {
            return None;
        }

        let arp = ArpPacket::new(eth.payload()).unwrap();

        Some(Device {
            name: String::from("test"),
            ip: arp.get_sender_proto_addr(),
            mac: arp.get_sender_hw_addr(),
            os: None,
            tcp_sent: false,
        })
    }
    
    fn handle_tcp_packet(&self, eth: &EthernetPacket, host: &Host) -> Option<Device> {
        let ipv4 = Ipv4Packet::new(&eth.payload()).unwrap();
        let source_ip = Ipv4Net::new(ipv4.get_source(), 24).unwrap();

        // Ignore packets from other networks
        if ipv4.get_destination() != host.ip().addr() || &source_ip.network() != &host.ip().network() {
            return None;
        }

        let tcp = TcpPacket::new(&eth.payload()[20..]).unwrap();
        const RST_ACK: u16 = TcpFlags::RST | TcpFlags::ACK;
        match tcp.get_flags() {
            RST_ACK => {
                match fingerprint::detect_os(&tcp, &ipv4) {
                    Ok(os) => {
                        return Some(Device {
                            name: String::from("test"),
                            ip: ipv4.get_destination(),
                            mac: eth.get_source(),
                            os: Some(os),
                            tcp_sent: true
                        })
                    },
                    Err(e) => {}
                }
            },
            _ => {}
        };

        return None
    }
}