use yimu::auth::{NoAuth, UsernamePasswordAuth};
use yimu::error::YimuError;
use yimu::server::{Dns, Server};

#[tokio::main]
async fn main() -> Result<(), YimuError> {
    env_logger::init();

    let builder = Server::builder()
        .ip("0.0.0.0".parse()?)
        .port(9011)
        .dns(Dns::Google)
        .add_authenticator(NoAuth)
        .add_authenticator(UsernamePasswordAuth::new(
            "yfaming".to_string(),
            "yfaming".to_string(),
        ));

    let server = builder.build().await?;
    server.run().await?;
    Ok(())
}
