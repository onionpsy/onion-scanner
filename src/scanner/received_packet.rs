
use crate::scanner::host::{Host};
use crate::scanner::{ScanningResult};
use crate::scanner::device::Device;

use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption, TcpPacket};
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use std::collections::HashMap;
use pnet::util::MacAddr;

pub enum ReceivedPacket<'a, 'b> {
    Arp(ArpPacket<'a>),
    Tcp(TcpPacket<'b>)
}


impl ReceivedPacket<'_, '_> {
    pub fn handle(&self, devices: &HashMap<&MacAddr, &Device>, host: &Host) -> Option<Device> {
        match &*self {
            ReceivedPacket::Arp(arp) => self.handle_arp_packet(&arp, devices, &host),
            ReceivedPacket::Tcp(tcp) => self.handle_tcp_packet(&tcp, devices, &host),
        }
    }

    fn handle_arp_packet(&self, arp: &pnet::packet::arp::ArpPacket, devices: &HashMap<&MacAddr, &Device>, host: &Host) -> Option<Device> {
        let mac = arp.get_sender_hw_addr();
        if devices.contains_key(&mac) {
            return None;
        }

        if &arp.get_sender_proto_addr() == &host.ip().addr() {
            return None;
        }

        let device = Device {
            name: String::from("test"),
            index: 0,
            ip: arp.get_sender_proto_addr(),
            mac: arp.get_sender_hw_addr()
        };

        // let _ = fingerprint::detect_os(&mut *tx, host, &device.ip, &device.mac);

        println!("{}", device.summarize());
        //result.devices.push(device);
        //index += 1;

        Some(device)
    }
    
    fn handle_tcp_packet(&self, tcp: &pnet::packet::tcp::TcpPacket, devices: &HashMap<&MacAddr, &Device>, host: &Host) -> Option<Device> {
        None
    }
}