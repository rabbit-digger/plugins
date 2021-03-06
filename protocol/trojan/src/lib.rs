use client::{TrojanNet, TrojanNetConfig};
use rd_interface::{registry::NetFactory, Registry, Result};

mod client;
mod tls;

impl NetFactory for TrojanNet {
    const NAME: &'static str = "trojan";
    type Config = TrojanNetConfig;
    type Net = Self;

    fn new(config: Self::Config) -> Result<Self> {
        TrojanNet::new(config)
    }
}

pub fn init(registry: &mut Registry) -> Result<()> {
    registry.add_net::<TrojanNet>();

    Ok(())
}
