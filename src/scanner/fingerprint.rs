use crate::scanner::received_packet::{TcpIpReceivedPacket};

use std::io::Result;
use serde::Deserialize;
use std::fs;
use super::device::{OS, OsFamily};
use std::str::FromStr;

const FILE_NAME: &str = "resources/fingerprint.csv";

#[derive(Deserialize)]
pub struct Fingerprint {
    pub os: OsFamily,
    pub version: Option<String>,
    pub ttl: u8,
    pub wsize: u16
}

lazy_static! {
    #[derive(Debug)]
    static ref FINGERPRINTS: Vec<Fingerprint> = {
        match fetch_finerprints_from_csv() {
            Ok(r) => r,
            Err(e) => panic!("Can't read fingerprint file {}", e)
        }
    };
}

pub fn detect_os<'a>(packet: &TcpIpReceivedPacket) -> Option<OS> {
    let mut os: Option<OS> = None;
    for (_, fingerprint) in FINGERPRINTS.iter().enumerate() {
        if (fingerprint.ttl == packet.ipv4.get_ttl() && fingerprint.wsize == packet.tcp.get_window()) ||
           (fingerprint.ttl == packet.ipv4.get_ttl() && fingerprint.wsize == 0 && os.is_none()) {
            os = Some(OS {
                family: fingerprint.os.clone(),
                version: fingerprint.version.clone()
            });
        }
    }

    os
}

pub fn fetch_finerprints_from_csv() -> Result<Vec<Fingerprint>> {
    let file = fs::File::open(FILE_NAME);
    let file = match file {
        Ok(file) => file,
        Err(e) => panic!("{} {}", e, FILE_NAME)
    };

    let mut reader = csv::Reader::from_reader(file);
    let mut fingerprints = Vec::new();
    for result in reader.records() {
        let row = result.unwrap();
        fingerprints.push(Fingerprint {
            os: OsFamily::from_str(row.get(0).unwrap()).unwrap_or(OsFamily::Other),
            version: match row.get(1) {
                Some(v) => {
                    if !v.is_empty() {
                        Some(String::from(v))
                    } else {
                        None
                    }
                }
                _ => None
            },
            ttl: row.get(2).unwrap().parse::<u8>().unwrap(),
            wsize: row.get(3).unwrap().parse::<u16>().unwrap()
        });
    }

    Ok(fingerprints)
}
