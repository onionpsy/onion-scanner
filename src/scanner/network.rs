extern crate pnet;

use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{MutableEthernetPacket, EtherTypes, EthernetPacket};
use pnet::datalink::{NetworkInterface};
use std::net::{Ipv4Addr, IpAddr};
use pnet::packet::{Packet, MutablePacket};
use std::io::{Result};
use pnet::datalink::{DataLinkSender, DataLinkReceiver};
use pnet::util::MacAddr;

pub fn read_arp_packet(rx: &mut dyn DataLinkReceiver) -> Result<Option<ArpPacket>> {
    match rx.next() {
        Ok(frame) => {
            let packet = EthernetPacket::new(frame).unwrap();
            match packet.get_ethertype() {
                EtherTypes::Arp => {
                    let arp = ArpPacket::new(&frame[MutableEthernetPacket::minimum_packet_size()..]).unwrap();
                    return Ok(Some(arp))
                },
                _ => return Ok(None)
            }
        },
        Err(e) => panic!("{}", e)
    }
}

pub fn send_arp_packet(tx: &mut dyn DataLinkSender, target_ip: Ipv4Addr, interface: &NetworkInterface) -> Result<()> {
    let source_ip = match interface.ips[0].ip() {
        IpAddr::V4(ip4) => ip4,
        IpAddr::V6(_) => unimplemented!()
    };

    let mut arp_buffer = [0u8; 28];
    let mut arp = MutableArpPacket::new(&mut arp_buffer).unwrap();
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Request);
    arp.set_sender_hw_addr(interface.mac.unwrap());
    arp.set_target_hw_addr(MacAddr::zero());
    arp.set_sender_proto_addr(source_ip);
    arp.set_target_proto_addr(target_ip);


    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet.set_source(interface.mac.unwrap());
    ethernet.set_destination(MacAddr::broadcast());
    ethernet.set_ethertype(EtherTypes::Arp);
    ethernet.set_payload(arp.packet_mut());

    return match tx.send_to(ethernet.packet(), None) {
        Some(_) => Ok(()),
        None => panic!("Error sending ARP packet")
    };
}