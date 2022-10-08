use std::net::{IpAddr, TcpStream};
use std::str::FromStr;
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::thread;

pub struct Sniffer {
    thread_num: usize,
    ip_address: IpAddr,
}

impl Sniffer {
    pub fn build(mut args: std::env::Args) -> Result<Sniffer, &'static str> {
        if args.len() < 2 {
            return Err("Not enough arguments.");
        } else if args.len() > 4 {
            return Err("Too many arguments.");
        }

        args.next(); // skip program name
        let args: Vec<_> = args.collect();

        let ip_address;
        let thread_num;

        if args.len() == 1 {
            // *.exe <ip_address>
            thread_num = 5; // default thread number
            ip_address = &args[0];
        } else if args.len() == 3 {
            // *.exe -j <thread_num> <ipaddr>
            if &args[0] == "-j" || &args[0] == "-J" {
                thread_num = match args[1].to_string().parse::<usize>() {
                    Ok(thread_num) => thread_num,
                    Err(_) => return Err("Not a valid thread number."),
                };
                ip_address = &args[2];
            } else {
                return Err("Arguments error.");
            }
        } else {
            return Err("Arguments error.");
        }

        if let Ok(ip_address) = IpAddr::from_str(&ip_address) {
            return Ok({
                Sniffer {
                    thread_num,
                    ip_address,
                }
            });
        } else {
            return Err("Not a valid ip address.");
        };
    }

    pub fn sniff(&self) -> Vec<u16> {
        let (tx, rx) = channel();

        // scan
        for i in 0..self.thread_num {
            let ip_address = Arc::new(self.ip_address);
            let new_tx = tx.clone();
            let port = i;
            let thread_num = self.thread_num;
            thread::spawn(move || scan(ip_address, new_tx, port, thread_num));
        }
        drop(tx);
        // collect result
        let mut result: Vec<_> = vec![];
        for p in rx {
            // println!("...{p}");
            result.push(p);
        }
        result.sort();
        return result;
    }
}

fn scan(ip_address: Arc<IpAddr>, tx: Sender<u16>, start_port: usize, thread_num: usize) {
    static MAX_PORTS_NUMBER: u16 = 65535;
    let mut port = (start_port + 1) as u16;
    loop {
        // scan
        println!("Checking port {port} ...");
        match TcpStream::connect((*ip_address, port as u16)) {
            Ok(_) => {
                tx.send(port).unwrap();
            }
            Err(_) => {}
        }
        if (MAX_PORTS_NUMBER - port) <= thread_num as u16 {
            break;
        }
        port += thread_num as u16;
    }
}
