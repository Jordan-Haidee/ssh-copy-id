# ssh-copy-id-windows
A simple implementation of ssh-copy-id in Rust on Windows


## Install
Download from [releases](https://github.com/Jordan-Haidee/ssh-copy-id/releases), 
or install from source:
```powershell
cargo install --git https://github.com/Jordan-Haidee/ssh-copy-id.git
```

## Usage
```powershell
Usage: sci.exe [OPTIONS] -p <PASSWORD> [ADDRESS]

Arguments:
  [ADDRESS]  Remote server address in the format of user@host:port

Options:
  -u <USER>          SSH login username
  -p <PASSWORD>      SSH login password
      --host <HOST>  Remote server IP address
      --port <PORT>  Remote server port [default: 22]
  -i <PUBKEY>        Path to the public key file [default: ~/.ssh/id_rsa.pub]
  -h, --help         Print help
```

### Examples

Input user|host|[port] at once, **recommended**: 
```powershell   
$ sci he@192.168.137.2:22 -p 666666
public key copied successfully
```
or, input user|host|[port] respectively by options: 
```powershell
$ sci -u he --host 192.168.137.2 -p 666666
public key copied successfully
```