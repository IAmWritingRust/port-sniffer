use std::net::{IpAddr, TcpStream};
use std::str::FromStr;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
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

        let ip_address: &String;
        let thread_num: usize;

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
        let current_port_number: Arc<Mutex<u32>> = Arc::new(Mutex::new(1));
        let (tx, rx) = channel();

        // scan
        for _ in 0..self.thread_num {
            let ip_address: Arc<IpAddr> = Arc::new(self.ip_address);
            let new_tx: Sender<u16> = tx.clone();
            let clone_current_port: Arc<Mutex<u32>> = Arc::clone(&current_port_number);
            thread::spawn(|| scan(ip_address, new_tx, clone_current_port));
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

fn scan(ip_address: Arc<IpAddr>, tx: Sender<u16>, current_port: Arc<Mutex<u32>>) {
    static MAX_PORTS_NUMBER: u32 = 65535;
    loop {
        let mut port: MutexGuard<'_, u32> = current_port.lock().unwrap();
        if *port > MAX_PORTS_NUMBER {
            break;
        }
        let c_port: u16 = *port as u16;
        *port += 1; // next port
        drop(port); // manual release lock

        // scan
        println!("Checking port {c_port} ...");
        match TcpStream::connect((*ip_address, c_port)) {
            Ok(_) => {
                tx.send(c_port).unwrap();
            }
            Err(_) => {}
        }
    }
}
