
use crate::scanner::host::{Host};
use crate::scanner::device::Device;
use crate::scanner::fingerprint;

use pnet::packet::arp::{ArpPacket};
use pnet::packet::tcp::{TcpPacket};
use pnet::packet::ipv4::{Ipv4Packet};
use ipnet::{Ipv4Net};
use pnet::packet::ethernet::{EthernetPacket};

pub enum ReceivedPacket<'a> {
    Arp(ArpReceivedPacket<'a>),
    TcpIp(TcpIpReceivedPacket<'a>)
}

pub struct ArpReceivedPacket<'a> {
    pub eth: EthernetPacket<'a>,
    pub arp: ArpPacket<'a>
}

pub struct TcpIpReceivedPacket<'a> {
    pub eth: EthernetPacket<'a>,
    pub tcp: TcpPacket<'a>,
    pub ipv4: Ipv4Packet<'a>
}

pub trait ReceivedPacketTrait<'a> {
    fn handle(&self, host: &Host) -> Option<Device>;
}

impl<'a> ReceivedPacketTrait<'a> for ArpReceivedPacket<'a> {
    fn handle(&self, host: &Host) -> Option<Device> {
        let mac = &self.eth.get_source();
        if mac == &host.interface.mac.unwrap() {
            return None;
        }

        Some(Device {
            name: String::from("test"),
            ip: self.arp.get_sender_proto_addr(),
            mac: self.arp.get_sender_hw_addr(),
            os: None,
            tcp_sent: false,
        })
    }
}

impl<'a> ReceivedPacketTrait<'a> for TcpIpReceivedPacket<'a> {
    fn handle(&self, host: &Host) -> Option<Device> {
        let source = Ipv4Net::new(self.ipv4.get_source(), 24).unwrap();

        if source.network() != host.ip().network() {
            return None;
        }

        Some(Device {
            name: String::from("test2"),
            ip: self.ipv4.get_source(),
            mac: self.eth.get_source(),
            os: fingerprint::detect_os(&self),
            tcp_sent: true
        })

        /*const RST_ACK: u16 = TcpFlags::RST | TcpFlags::ACK;
        match self.tcp.get_flags() {
            RST_ACK => {
                let os = fingerprint::detect_os(&self);

                Some(Device {
                    name: String::from("test1"),
                    ip: self.ipv4.get_source(),
                    mac: self.eth.get_source(),
                    os: os,
                    tcp_sent: true,
                })
            },
        }*/
    }
}