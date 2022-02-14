extern crate pnet;

use pnet::packet::tcp;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption, TcpPacket};
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ethernet::{MutableEthernetPacket, EtherTypes, EthernetPacket};
use pnet::datalink::{NetworkInterface};
use std::net::{Ipv4Addr, IpAddr};
use pnet::packet::{Packet, MutablePacket};
use std::io::{Result};
use pnet::datalink::{DataLinkSender};
use pnet::util::MacAddr;
use pnet::packet::ip::IpNextHeaderProtocols;

use crate::scanner::host::{Host};
use crate::scanner::device::{Device};
use crate::scanner::received_packet::{ArpReceivedPacket, TcpIpReceivedPacket, ReceivedPacket};

pub const TCP_BUFFER_SIZE: usize = 20;
pub const ETH_BUFFER_SIZE: usize = 14;
pub const ARP_BUFFER_SIZE: usize = 28;
pub const IPV4_BUFFER_SIZE: usize = 20;

pub fn read_packets<'a>(frame: &'a [u8]) -> Option<ReceivedPacket<'a>> {
    let eth = EthernetPacket::new(&frame).unwrap();
    match eth.get_ethertype() {
        EtherTypes::Arp => {
            Some(ReceivedPacket::Arp(ArpReceivedPacket {
                eth: eth,
                arp: ArpPacket::new(&frame[ETH_BUFFER_SIZE..]).unwrap() 
           }))
        },
        EtherTypes::Ipv4 => {
            match TcpPacket::new(&frame[ETH_BUFFER_SIZE + IPV4_BUFFER_SIZE..]) {
                Some(tcp) => {
                    Some(ReceivedPacket::TcpIp(TcpIpReceivedPacket {
                        eth: eth,
                        tcp: tcp,
                        ipv4: Ipv4Packet::new(&frame[ETH_BUFFER_SIZE..]).unwrap()
                    }))
                },
                _ => { println!("Cannot decrypt TCP packet"); None }
            }

        },
        _ => { None }
    }
}

pub fn send_arp_packet(tx: &mut dyn DataLinkSender, interface: &NetworkInterface, target_ip: &Ipv4Addr) -> Result<()> {
    let source_ip = get_source_ip(interface);

    let mut arp_buffer = [0u8; ARP_BUFFER_SIZE];
    let mut arp = MutableArpPacket::new(&mut arp_buffer).unwrap();
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Request);
    arp.set_sender_hw_addr(interface.mac.unwrap());
    arp.set_target_hw_addr(MacAddr::zero());
    arp.set_sender_proto_addr(source_ip);
    arp.set_target_proto_addr(*target_ip);

    let mut ethernet_buffer = [0u8; ARP_BUFFER_SIZE + ETH_BUFFER_SIZE];
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

fn get_source_ip(interface: &NetworkInterface) -> Ipv4Addr {
    match interface.ips[0].ip() {
        IpAddr::V4(ip4) => ip4,
        IpAddr::V6(_) => unimplemented!()
    }
}

pub fn send_tcp_packet(tx: &mut dyn DataLinkSender, host: &Host, device: &Device) -> Result<()> {
    let source_ip = &host.ip().addr();
    const PAYLOAD_SIZE: usize = 12;

    let mut packet_buffer = [0u8; ETH_BUFFER_SIZE + IPV4_BUFFER_SIZE + TCP_BUFFER_SIZE + PAYLOAD_SIZE];

    let mut ethernet = MutableEthernetPacket::new(&mut packet_buffer[..ETH_BUFFER_SIZE]).unwrap();
    ethernet.set_source(host.interface.mac.unwrap());
    ethernet.set_destination(device.mac);
    ethernet.set_ethertype(EtherTypes::Ipv4);

    let mut ipv4 = MutableIpv4Packet::new(&mut packet_buffer[ETH_BUFFER_SIZE..]).unwrap(); // 20
    ipv4.set_version(4);
    ipv4.set_total_length((ETH_BUFFER_SIZE + IPV4_BUFFER_SIZE + TCP_BUFFER_SIZE - 2) as u16);
    ipv4.set_header_length(5);
    ipv4.set_identification(rand::random::<u16>());
    ipv4.set_flags(Ipv4Flags::DontFragment);
    ipv4.set_ttl(128);
    ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ipv4.set_source(*source_ip);
    ipv4.set_destination(device.ip);
    let checksum = pnet::packet::ipv4::checksum(&ipv4.to_immutable());
    ipv4.set_checksum(checksum);

    let mut tcp = MutableTcpPacket::new(&mut packet_buffer[IPV4_BUFFER_SIZE + ETH_BUFFER_SIZE..]).unwrap(); // 20
    tcp.set_source(rand::random::<u16>());
    tcp.set_destination(rand::random::<u16>());
    tcp.set_flags(TcpFlags::SYN); // SYN-SENT
    tcp.set_window(64240);
    tcp.set_data_offset(8);
    tcp.set_urgent_ptr(0);
    tcp.set_sequence(rand::random::<u32>());
    tcp.set_options(&[TcpOption::mss(1460), TcpOption::nop(), TcpOption::wscale(8), TcpOption::nop(), TcpOption::nop(), TcpOption::sack_perm()]);
    let checksum = tcp::ipv4_checksum(&tcp.to_immutable(), source_ip, &device.ip);
    tcp.set_checksum(checksum);

    return match tx.send_to(&packet_buffer, None) {
        Some(_p) => {
            Ok(())
        },
        None => panic!("Error sending TCP packet")
    }
}