use crate::scanner::network;
use crate::scanner::host::{Host};
use crate::scanner::device::{Device};

use std::net::{Ipv4Addr, IpAddr};
use pnet::datalink::{DataLinkSender, DataLinkReceiver, Config, Channel, NetworkInterface};
use pnet::util::MacAddr;
use std::io::Result;
use pnet::packet::tcp::{TcpFlags, TcpOption, TcpPacket};
use pnet::packet::ipv4::Ipv4Packet;


pub fn detect_os(tcp: &TcpPacket, ip: &Ipv4Packet) -> Result<String> {
    Ok(String::from("OS"))
}

