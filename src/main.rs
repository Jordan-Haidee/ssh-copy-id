use clap::Parser;
use ssh2::Session;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::exit;

// define command line arguments
#[derive(Parser, Debug)]
#[command(
    name = "ssh-copy-id",
    about = "A simple implementation of ssh-copy-id in Rust on Windows",
    version
)]
struct Args {
    /// Remote server address in the format of user@host:port
    #[clap(value_parser = parse_address)]
    address: Option<(String, String, Option<String>)>,

    /// SSH login username
    #[clap(short = 'u')]
    user: Option<String>,

    /// SSH login password
    #[clap(short = 'p')]
    password: String,

    /// Remote server IP address
    #[clap(long)]
    host: Option<String>,

    /// Remote server port
    #[clap(long, default_value = "22")]
    port: String,

    /// Path to the public key file
    #[clap(short = 'i', default_value = "~/.ssh/id_rsa.pub")]
    pubkey: String,
}

type Error = Box<dyn std::error::Error>;

fn parse_address(input: &str) -> Result<(String, String, Option<String>), String> {
    //  split user and host/port part
    let (user, host_port) = input.split_once('@').expect("invalid address format");

    // split host and port from host/port part
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (host_port, None),
    };

    Ok((
        user.to_string(),
        host.to_string(),
        port.map(|s| s.to_string()),
    ))
}

fn parse_args() -> (String, String, String, String, String) {
    let args = Args::parse();
    let (user, host, port) = match args.address {
        Some((user, host, port)) => {
            if let Some(p) = port {
                (user, host, p)
            } else {
                (user, host, args.port)
            }
        }
        None => match (args.host, args.user) {
            (Some(host), Some(user)) => (user, host, args.port),
            _ => {
                eprintln!("address or host and user must be provided");
                exit(-1);
            }
        },
    };
    let (password, pubkey) = (args.password, args.pubkey);
    (user, host, port, password, pubkey)
}

fn create_ssh_session(
    user: &str,
    host: &str,
    port: &str,
    password: &str,
) -> Result<Session, Error> {
    // 1. create tcp connection
    let addr = format!("{}:{}", host, port);
    let tcp = TcpStream::connect(addr)?;

    // 2. init ssh session
    let mut session = Session::new()?;
    session.set_tcp_stream(tcp);
    session.handshake()?;

    // 3. authentication of user
    session.userauth_password(user, password)?;

    if !session.authenticated() {
        eprintln!("authentication failed");
        exit(-1);
    }

    // 4. return authenticated session
    Ok(session)
}

fn read_auth_keys(session: &Session) -> Result<String, Error> {
    let p = Path::new(".ssh/authorized_keys");
    if let Ok((mut remote_file, _)) = session.scp_recv(p) {
        let mut contents = Vec::new();
        remote_file.read_to_end(&mut contents)?;

        // Close the channel and wait for the whole content to be tranferred
        remote_file.send_eof()?;
        remote_file.wait_eof()?;
        remote_file.close()?;
        remote_file.wait_close()?;
        return Ok(String::from_utf8(contents)?);
    } else {
        Ok(String::new())
    }
}

fn write_auth_keys(session: &Session, pubkey: &str) -> Result<(), Error> {
    let p = Path::new(".ssh/authorized_keys");
    let s = pubkey.as_bytes();
    let mut remote_file = session.scp_send(p, 0o644, s.len() as u64, None)?;
    let res = remote_file.write(s);

    // Close the channel and wait for the whole content to be tranferred
    remote_file.send_eof()?;
    remote_file.wait_eof()?;
    remote_file.close()?;
    remote_file.wait_close()?;
    res.map(|_| ()).map_err(|e| e.into())
}

fn read_local_pubkey(pubkey_path: &str) -> Result<String, Error> {
    let p = shellexpand::tilde(pubkey_path);
    dbg!(&p);
    let pubkey_string = std::fs::read_to_string(p.as_ref())?;
    Ok(pubkey_string)
}

fn main() -> Result<(), Error> {
    // parse command line arguments
    let (user, host, port, password, pubkey) = parse_args();

    // create ssh session
    let session = create_ssh_session(&user, &host, &port, &password)?;

    // read authorized keys
    let mut remote_authorized_keys = read_auth_keys(&session)?;

    // read local public key
    let pubkey = read_local_pubkey(&pubkey)?;

    // copy public key to remote authorized keys
    if !remote_authorized_keys.contains(&pubkey) {
        remote_authorized_keys.push_str(&pubkey);
        match write_auth_keys(&session, &remote_authorized_keys) {
            Ok(_) => {
                println!("public key copied successfully");
            }
            Err(e) => {
                eprintln!("failed to copy public key: {}", e);
            }
        }
    } else {
        println!("public key already exists, so nothing to do");
    }

    // close session
    session.disconnect(None, "closed", None)?;

    Ok(())
}
