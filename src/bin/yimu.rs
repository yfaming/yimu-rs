use std::net::{IpAddr, Ipv4Addr};
use std::process;
use yimu::auth::{NoAuth, UsernamePasswordAuth};
use yimu::dns::Dns;
use yimu::error::YimuError;
use yimu::server::Server;

#[derive(Debug, clap::Parser)]
#[clap(name = "yimu", about = "yimu is a socks5 server")]
pub struct Opt {
    #[clap(
        long = "port",
        default_value = "9011",
        help = "the port yimu listens to"
    )]
    pub port: u16,

    #[clap(
        long = "dns",
        default_value = "google",
        help = "the dns resolver to use. allowed values are: system, google, cloudflare, quad9, <ip> and <ip:port>."
    )]
    pub dns: Dns,

    #[clap(
        long = "no_auth",
        help = "if specified, it's allowed to connect to yimu without password. \
        Note: can be used together with auth_username and auth_password"
    )]
    pub no_auth: bool,

    #[clap(
        long = "auth_username",
        help = "specify username for authentication, should be used along with auth_password"
    )]
    pub auth_username: Option<String>,

    #[clap(
        long = "auth_password",
        help = "specify password for authentication, should be used along with auth_username"
    )]
    pub auth_password: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), YimuError> {
    env_logger::init();

    let opt: Opt = clap::Parser::parse();
    if (opt.auth_username.is_some() && opt.auth_password.is_none())
        || (opt.auth_username.is_none() && opt.auth_password.is_some())
    {
        println!("auth_username and auth_password should both be specified.");
        process::exit(1);
    }

    let mut builder = Server::builder()
        .ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        .port(opt.port)
        .dns(opt.dns);

    if opt.no_auth {
        builder = builder.add_authenticator(NoAuth);
    }
    if opt.auth_username.is_some() {
        let username = opt.auth_username.clone().unwrap();
        let password = opt.auth_password.clone().unwrap();
        builder = builder.add_authenticator(UsernamePasswordAuth::new(username, password));
    }

    let server = builder.build().await?;
    server.run().await?;
    Ok(())
}
