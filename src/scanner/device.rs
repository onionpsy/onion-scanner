use pnet::datalink::{MacAddr};
use std::net::{Ipv4Addr};
use colored::*;
use serde::Deserialize;
use std::fmt;
use std::str::FromStr;

#[derive(Deserialize, Clone)]
pub enum OsFamily { Linux, Windows, BSD, Cisco, MacOS, Other }

impl fmt::Display for OsFamily {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            OsFamily::Linux => write!(f, "Linux"),
            OsFamily::Windows => write!(f, "Windows"),
            OsFamily::Other => write!(f, "Other"),
            OsFamily::BSD => write!(f, "BSD"),
            OsFamily::Cisco => write!(f, "Cisco"),
            OsFamily::MacOS => write!(f, "MacOS"),
            _ => write!(f, "Unknown")
        }
    }
}

impl FromStr for OsFamily {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "Linux" => Ok(OsFamily::Linux),
            "Windows" => Ok(OsFamily::Windows),
            "MacOS" => Ok(OsFamily::MacOS),
            "FreeBSD" => Ok(OsFamily::BSD),
            "Cisco" => Ok(OsFamily::Cisco),
            _ => Err(())
        }
    }
}

pub struct Device {
    pub name: String,
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
    pub os: Option<OS>,
    pub tcp_sent: bool
}

#[derive(Deserialize)]
pub struct OS {
    pub family: OsFamily,
    pub version: Option<String>
}

impl Device {
    pub fn summarize(&self) -> String {
        // let name = &self.name[..self.name.chars().map(|c| c.len_utf8()).take(10).sum()];

        format!(" {: <12}  {: <15}  {: <20}",
            self.mac.to_string().color("purple"),
            self.ip.to_string().color("green"),
            match &self.os {
                Some(os) => {
                    let v = match &os.version {
                        Some(version) => version.color("cyan"),
                        None => "".color("")
                    };
                    format!("{} {}", os.family, v).color("cyan")
                },
                None => "None".color("cyan")
            }
        )
    }
}