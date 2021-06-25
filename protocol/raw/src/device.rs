use rd_interface::{Error, Result};
use tokio_smoltcp::device::Interface;

#[cfg(unix)]
fn get_rawsock() -> &'static rawsock::pcap::Library {
    use once_cell::sync::OnceCell;
    use rawsock::{pcap::Library, traits::Library as _};
    static LIB: OnceCell<Library> = OnceCell::new();
    &LIB.get_or_init(|| Library::open_default_paths().expect("Failed to open libpcap"))
}

#[cfg(unix)]
pub fn get_by_device(name: &str) -> Result<impl Interface> {
    use rawsock::traits::Library;
    use rd_interface::error::map_other;
    use tokio::sync::mpsc::{Receiver, Sender};
    use tokio_smoltcp::util::ChannelCapture;

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

#[cfg(windows)]
fn get_device(name: &str) -> Result<Device> {
    let mut devices = Device::list().context("Failed to list device")?;

    if let Some(id) = devices.iter().position(|d| d.name == name) {
        Ok(devices.remove(id))
    } else {
        Err(Error::Other(
            format!(
                "Failed to find device {} from {:?}",
                name,
                devices
                    .into_iter()
                    .map(|i| format!("[{}] {}", i.name, i.desc.unwrap_or_default()))
                    .collect::<Vec<String>>()
            )
            .into(),
        ))
    }
}

#[cfg(windows)]
pub fn get_by_device(name: &str) -> Result<impl Interface> {
    let device = get_device(name)?;
    use pcap::{Capture, Device};
    use tokio::sync::mpsc::{Receiver, Sender};
    use tokio_smoltcp::util::ChannelCapture;

    let mut cap = Capture::from_device(device.clone())
        .context("Failed to capture device")?
        .promisc(true)
        .immediate_mode(true)
        .timeout(5)
        .open()
        .context("Failed to open device")?;
    let mut send = Capture::from_device(device)
        .context("Failed to capture device")?
        .promisc(true)
        .immediate_mode(true)
        .timeout(5)
        .open()
        .context("Failed to open device")?;

    let recv = move |tx: Sender<Vec<u8>>| loop {
        let p = match cap.next().map(|p| p.to_vec()) {
            Ok(p) => p,
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                eprintln!("Error: {:?}", e);
                break;
            }
        };
        tx.blocking_send(p).unwrap();
    };
    let send = move |mut rx: Receiver<Vec<u8>>| {
        while let Some(pkt) = rx.blocking_recv() {
            send.sendpacket(pkt).unwrap();
        }
    };
    let capture = ChannelCapture::new(recv, send);
    Ok(capture)
}
