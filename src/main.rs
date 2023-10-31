use port_sniffer::Sniffer;

fn main() {
    // Add explicit type annotations
    let sniffer: Sniffer = Sniffer::build(std::env::args()).unwrap_or_else(|err| {
        println!("Error: {}", err);
        println!("Usage: *.exe [-j <thread_num>] <ip_address>.");
        std::process::exit(1)
    });
    let result: Vec<u16> = sniffer.sniff();
    println!("{}",result.len());
    for port in result {
        println!("{port}");
    }
}
