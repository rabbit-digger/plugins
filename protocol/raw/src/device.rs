use once_cell::sync::OnceCell;
use rawsock::traits::Library;
use rd_interface::{error::map_other, Error, Result};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_smoltcp::{device::Interface, util::ChannelCapture};

fn get_rawsock() -> &'static Box<dyn Library> {
    static LIB: OnceCell<Box<dyn Library>> = OnceCell::new();
    &LIB.get_or_init(|| {
        #[cfg(unix)]
        return Box::new(
            rawsock::pcap::Library::open_default_paths().expect("Failed to open libpcap"),
        );

        #[cfg(windows)]
        return Box::new(
            rawsock::wpcap::Library::open_default_paths().expect("Failed to open wpcap"),
        );
    })
}

pub fn get_by_device(name: &str) -> Result<impl Interface> {
    let lib = get_rawsock();
    lib.all_interfaces()
        .map_err(map_other)?
        .into_iter()
        .find(|i| i.name == name)
        .ok_or(Error::Other("Failed to find interface".into()))?;

    let dev = lib.open_interface_arc(&name).map_err(map_other)?;
    let send_dev = dev.clone();
    let recv = move |tx: Sender<Vec<u8>>| {
        dev.loop_infinite_dyn(&|p| {
            tx.blocking_send(p.to_vec()).unwrap();
        })
        .unwrap();
    };
    let send = move |mut rx: Receiver<Vec<u8>>| {
        while let Some(pkt) = rx.blocking_recv() {
            send_dev.send(&pkt).unwrap();
        }
    };
    let capture = ChannelCapture::new(recv, send);
    Ok(capture)
}
