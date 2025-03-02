use clap::{Arg, Command};
use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;
// use std::path::PathBuf;

fn run_remote_command(
    session: &Session,
    command: &str,
) -> Result<(String, i32), Box<dyn std::error::Error>> {
    // create a new channel for every command
    let mut channel = session.channel_session()?;
    channel.exec(command)?;

    let mut output = String::new();
    channel.read_to_string(&mut output)?;
    let exit_status = channel.exit_status()?;
    channel.close()?;
    Ok((output, exit_status))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("ssh-copy-id")
        .about("Copies the SSH public key to the remote server's authorized_keys file")
        .arg(
            Arg::new("user")
                .short('u')
                .required(true)
                .help("SSH login username"),
        )
        .arg(
            Arg::new("password")
                .short('p')
                .required(true)
                .help("SSH login password"),
        )
        .arg(
            Arg::new("host")
                .long("host")
                .required(true)
                .help("Remote server IP address"),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("22")
                .help("Remote server port"),
        )
        .arg(
            Arg::new("pubkey")
                .short('i')
                .default_value("~/.ssh/id_rsa.pub")
                .help("Path to the public key file"),
        )
        .get_matches();

    // 1. create tcp connection
    let host: &String = matches.get_one("host").unwrap();
    let port: &String = matches.get_one("port").unwrap();
    let addr = format!("{}:{}", host, port);
    let tcp = TcpStream::connect(addr)?;

    // 2. init ssh session
    let mut session = Session::new()?;
    session.set_tcp_stream(tcp);
    session.handshake()?;

    // 3. authentication of user
    let user: &String = matches.get_one("user").expect("user not found");
    let password: &String = matches.get_one("password").expect("password not found");
    session.userauth_password(user, password)?;
    if !session.authenticated() {
        eprintln!("authentication failed");
        return Ok(());
    }

    // 5. read authorized keys
    let remote_home_dir = run_remote_command(&session, "pwd")?
        .0
        .trim_end()
        .to_string();
    let remote_authorized_path = format!("{}/.ssh/authorized_keys", remote_home_dir);
    let authorized_keys =
        run_remote_command(&session, &format!("cat {}", remote_authorized_path))?.0;

    // 6. read local public key
    let local_pubkey_path: &String = matches.get_one("pubkey").expect("pubkey not found");
    let mut local_pubkey_path = local_pubkey_path.to_owned();
    if local_pubkey_path.contains("~") {
        local_pubkey_path = local_pubkey_path.replace(
            "~",
            &dirs::home_dir()
                .expect("can't get home dir locally")
                .display()
                .to_string(),
        );
    }
    let pubkey = std::fs::read_to_string(&local_pubkey_path)?;

    // 7. copy public key to remote authorized keys
    if !authorized_keys.contains(&pubkey) {
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

    // 8. close session
    session.disconnect(None, "closed", None)?;

    Ok(())
}
