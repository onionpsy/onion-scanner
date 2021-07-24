use crate::scanner::network;
use crate::scanner::host::{Host};

use std::net::{Ipv4Addr, IpAddr};
use pnet::datalink::{DataLinkSender, DataLinkReceiver, Config, Channel, NetworkInterface};
use pnet::util::MacAddr;
use std::io::Result;


pub fn detect_os(tx: &mut dyn DataLinkSender, host: &Host, target_ip: &Ipv4Addr, target_mac: &MacAddr) -> Result<()> {
    network::send_tcp_packet(tx, &host, target_ip, target_mac)
}

