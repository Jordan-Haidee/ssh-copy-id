use clap::Parser;
use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;
use std::process::exit;

// define command line arguments
#[derive(Parser, Debug)]
#[command(
    name = "ssh-copy-id",
    about = "A simple implementation of ssh-copy-id in Rust on Windows"
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
) -> Result<Session, Box<dyn std::error::Error>> {
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

fn read_auth_keys(session: &Session) -> Result<(String, String), Box<dyn std::error::Error>> {
    let remote_home_dir = run_remote_command(&session, "pwd")?
        .0
        .trim_end()
        .to_string();
    let remote_authorized_path = format!("{}/.ssh/authorized_keys", remote_home_dir);
    if run_remote_command(session, &format!("ls {remote_authorized_path}"))?.1 != 0 {
        run_remote_command(session, &format!("echo > {remote_authorized_path}"))?;
    }
    let authorized_keys =
        run_remote_command(&session, &format!("cat {}", remote_authorized_path))?.0;
    Ok((authorized_keys, remote_authorized_path))
}

fn read_local_pubkey(pubkey_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let p = shellexpand::tilde(pubkey_path);
    let pubkey_string = std::fs::read_to_string(p.as_ref())?;
    Ok(pubkey_string)
}

fn run_remote_command(
    session: &Session,
    command: &str,
) -> Result<(String, i32), Box<dyn std::error::Error>> {
    // create new channel for every command
    let mut channel = session.channel_session()?;
    channel.exec(command)?;

    let mut output = String::new();
    channel.read_to_string(&mut output)?;
    let exit_status = channel.exit_status()?;
    channel.close()?;
    Ok((output, exit_status))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // parse command line arguments
    let (user, host, port, password, pubkey) = parse_args();

    // create ssh session
    let session = create_ssh_session(&user, &host, &port, &password)?;

    // read authorized keys
    let (remote_authorized_keys, remote_authorized_path) = read_auth_keys(&session)?;

    // read local public key
    let pubkey = read_local_pubkey(&pubkey)?;

    // copy public key to remote authorized keys
    if !remote_authorized_keys.contains(&pubkey) {
        let exit_code = run_remote_command(
            &session,
            &format!("echo \'{pubkey}\' >> {}", remote_authorized_path),
        )?
        .1;
        if exit_code == 0 {
            println!("public key copied successfully");
        } else {
            eprintln!("failed to copy public key");
        }
    } else {
        println!("public key already exists, so nothing to do");
    }

    // close session
    session.disconnect(None, "closed", None)?;

    Ok(())
}
