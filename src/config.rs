use clap::{Arg, App};

pub struct Config {
    pub interface_index: u32,
    pub verbose: u32
}

impl Config {
    pub fn parse(interface_indexes: &Vec<u32>) -> Result<Config, String> {
        let matches = App::new("rscanner")
            .version("0.1")
            .author("onionpsy <onionpsy@protonmail.com>")
            .about("ARP Lan scanner")
            .arg(Arg::new("interface")
                .short('i')
                .long("interface")
                .value_name("INTERFACE")
                .about("Choose the network interface")
                .required(true)
            )
            .arg(Arg::new("v")
                .short('v')
                .multiple_occurrences(true)
                .takes_value(true)
                .about("Sets the level of verbosity")
            )
            .get_matches();
        

        let verbosity = matches.occurrences_of("verbose") as u32;
        let interface: u32 = matches
            .value_of("interface")
            .unwrap()
            .trim()
            .parse::<u32>()
            .expect("Interface should be a number");
        
        if !interface_indexes.contains(&interface) {
            return Err(format!("{} is not a valid interface.\nUse one of these {:?}", &interface, interface_indexes)) // TODO show iface name/ip
        }

        Ok(Config {
            interface_index: interface,
            verbose: match verbosity {
                0..=2 => verbosity,
                _ => 2
            }
        })
    }
}