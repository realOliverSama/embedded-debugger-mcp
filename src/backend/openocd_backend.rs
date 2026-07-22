//! OpenOCD engine via GDB Remote Serial Protocol (optional backend).
//!
//! Requires an already-running `openocd` exposing its GDB port (default :3333),
//! e.g. `openocd -f interface/stlink.cfg -f target/stm32f4x.cfg`. Memory access
//! uses native RSP (`m`/`M`); execution control uses OpenOCD `monitor` commands
//! (synchronous, so `run` returns promptly instead of blocking like `c`).

use async_trait::async_trait;

use super::rsp::{decode_hex, encode_hex, RspClient};
use super::{
    BackendKind, BreakpointAddressContext, CoreRegId, CoreState, DebugBackend, MaskNormalization,
    SpecialRegisters, SramLaunchState,
};
use crate::error::{DebugError, Result};

pub struct OpenOcdBackend {
    rsp: RspClient,
    address: String,
}

impl OpenOcdBackend {
    pub async fn connect(address: &str) -> Result<Self> {
        let rsp = RspClient::connect(address).await?;
        Ok(Self {
            rsp,
            address: address.to_string(),
        })
    }

    pub fn address(&self) -> &str {
        &self.address
    }
}

/// Candidate openocd register names for a role, across architectures.
///
/// openocd resolves register names per target (ARM: pc/sp/lr; Xtensa: pc/a1/a0;
/// RISC-V: pc/sp/ra), so we ask by NAME via `monitor reg <name>` rather than
/// guessing a gdb register number. `p<n>` is architecture-specific and, on the
/// esp32-s3 Xtensa target, the GDB target description exposes no register map
/// at all — but `monitor reg pc` returns the correct value. Verified on real S3.
fn role_register_names(reg: CoreRegId) -> &'static [&'static str] {
    match reg {
        CoreRegId::Pc => &["pc"],
        CoreRegId::Sp => &["sp", "a1"],
        CoreRegId::Lr => &["lr", "ra", "a0"],
    }
}

/// Parse a value out of openocd's `reg` output, e.g. "pc (/32): 0x40381796".
fn parse_reg_value(text: &str) -> Option<u32> {
    let idx = text.find("0x")?;
    let hex: String = text[idx + 2..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    u64::from_str_radix(&hex, 16).ok().map(|v| v as u32)
}

fn expect_ok(reply: &str, what: &str) -> Result<()> {
    if reply == "OK" {
        Ok(())
    } else if let Some(code) = reply.strip_prefix('E') {
        Err(DebugError::InternalError(format!(
            "OpenOCD {} error E{}",
            what, code
        )))
    } else {
        // Some stubs answer empty for unsupported; treat non-error as success.
        Ok(())
    }
}

#[async_trait]
impl DebugBackend for OpenOcdBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::OpenOcd
    }

    async fn read_bytes(&mut self, address: u64, len: usize) -> Result<Vec<u8>> {
        let reply = self
            .rsp
            .command(&format!("m{:x},{:x}", address, len))
            .await?;
        if let Some(code) = reply.strip_prefix('E') {
            return Err(DebugError::MemoryAccessFailed(format!(
                "OpenOCD read 0x{:08X} error E{}",
                address, code
            )));
        }
        decode_hex(&reply)
    }

    async fn write_bytes(&mut self, address: u64, data: &[u8]) -> Result<()> {
        let reply = self
            .rsp
            .command(&format!(
                "M{:x},{:x}:{}",
                address,
                data.len(),
                encode_hex(data)
            ))
            .await?;
        expect_ok(&reply, "write")
    }

    async fn halt(&mut self) -> Result<()> {
        self.rsp.monitor("halt").await.map(|_| ())
    }

    async fn run(&mut self) -> Result<()> {
        self.rsp.monitor("resume").await.map(|_| ())
    }

    async fn step(&mut self) -> Result<()> {
        self.rsp.monitor("step").await.map(|_| ())
    }

    async fn reset(&mut self, halt_after: bool) -> Result<()> {
        let cmd = if halt_after {
            "reset halt"
        } else {
            "reset run"
        };
        self.rsp.monitor(cmd).await.map(|_| ())
    }

    async fn core_reg(&mut self, reg: CoreRegId) -> Result<u32> {
        // Ask openocd for the register by name; it resolves names per target
        // architecture, so this works without hardcoding gdb register numbers.
        // Output looks like "pc (/32): 0x40381796".
        for name in role_register_names(reg) {
            if let Ok(out) = self.rsp.monitor(&format!("reg {}", name)).await {
                if let Some(value) = parse_reg_value(&out) {
                    return Ok(value);
                }
            }
        }
        Err(DebugError::InternalError(format!(
            "could not read register {:?} via 'monitor reg' (tried {:?})",
            reg,
            role_register_names(reg)
        )))
    }

    async fn status(&mut self) -> Result<CoreState> {
        let reply = self.rsp.command("?").await?;
        Ok(if reply.starts_with('T') || reply.starts_with('S') {
            CoreState::Halted
        } else {
            CoreState::Unknown
        })
    }

    async fn set_hw_breakpoint(&mut self, address: u64) -> Result<()> {
        let reply = self.rsp.command(&format!("Z1,{:x},2", address)).await?;
        expect_ok(&reply, "set breakpoint")
    }

    async fn clear_hw_breakpoint(&mut self, address: u64) -> Result<()> {
        let reply = self.rsp.command(&format!("z1,{:x},2", address)).await?;
        expect_ok(&reply, "clear breakpoint")
    }

    async fn breakpoint_address_context(&self) -> Result<BreakpointAddressContext> {
        // The GDB RSP link to OpenOCD exposes neither the target memory map nor
        // a reliable core architecture, so executability cannot be verified on
        // this backend. Report "unknown"; the tool layer applies a safe
        // rejection policy instead of trusting unverifiable addresses.
        Ok(BreakpointAddressContext {
            is_cortex_m: false,
            regions: None,
        })
    }

    async fn prepare_sram_launch(&mut self, _launch: SramLaunchState) -> Result<()> {
        Err(DebugError::InternalError(
            "SRAM launch is not supported on the OpenOCD backend; reconnect with backend=\"probe-rs\""
                .to_string(),
        ))
    }

    async fn read_special_registers(&mut self) -> Result<SpecialRegisters> {
        Err(DebugError::InternalError(
            "read_special_registers is not supported on the OpenOCD backend; reconnect with backend=\"probe-rs\""
                .to_string(),
        ))
    }

    async fn clear_interrupt_masks(&mut self) -> Result<MaskNormalization> {
        Err(DebugError::InternalError(
            "clear_interrupt_masks is not supported on the OpenOCD backend; reconnect with backend=\"probe-rs\""
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{CoreRegId, CoreState, DebugBackend};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn checksum(bytes: &[u8]) -> u8 {
        bytes.iter().fold(0u8, |a, b| a.wrapping_add(*b))
    }

    fn hex_encode(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect()
    }

    /// Read one RSP packet payload from a socket ($payload#cc). None on EOF.
    async fn read_packet(sock: &mut TcpStream) -> Option<String> {
        let mut b = [0u8; 1];
        loop {
            if sock.read_exact(&mut b).await.is_err() {
                return None;
            }
            if b[0] == b'$' {
                break;
            }
        }
        let mut data = Vec::new();
        loop {
            sock.read_exact(&mut b).await.ok()?;
            if b[0] == b'#' {
                break;
            }
            data.push(b[0]);
        }
        let mut cks = [0u8; 2];
        sock.read_exact(&mut cks).await.ok()?;
        String::from_utf8(data).ok()
    }

    async fn send_packet(sock: &mut TcpStream, payload: &str) {
        let framed = format!("${}#{:02x}", payload, checksum(payload.as_bytes()));
        sock.write_all(framed.as_bytes()).await.unwrap();
        sock.flush().await.unwrap();
    }

    /// Minimal GDB-RSP server that answers the subset our client uses.
    async fn mock_rsp_server(listener: TcpListener) {
        let (mut sock, _) = listener.accept().await.unwrap();
        loop {
            let pkt = match read_packet(&mut sock).await {
                Some(p) => p,
                None => break,
            };
            // Ack the client's packet.
            sock.write_all(b"+").await.unwrap();

            // Build the response packet(s). "OK" acks writes, monitor commands,
            // and breakpoints. `monitor reg pc` replies (like real openocd) with
            // the register line as a single hex-encoded packet (no O prefix, no
            // trailing OK).
            let responses: Vec<String> = if pkt.starts_with('m') {
                vec!["deadbeef".to_string()] // 4 bytes for a read
            } else if pkt == "?" {
                vec!["T05".to_string()] // halted
            } else if let Some(hexcmd) = pkt.strip_prefix("qRcmd,") {
                let cmd = String::from_utf8(hex_decode(hexcmd)).unwrap_or_default();
                if cmd == "reg pc" {
                    let line = "pc (/32): 0x08000100\n";
                    vec![hex_encode(line.as_bytes())]
                } else {
                    vec!["OK".to_string()]
                }
            } else if pkt.starts_with('M') || pkt.starts_with('Z') || pkt.starts_with('z') {
                vec!["OK".to_string()]
            } else {
                vec![String::new()]
            };

            for r in &responses {
                send_packet(&mut sock, r).await;
                let mut ack = [0u8; 1];
                if sock.read_exact(&mut ack).await.is_err() {
                    return;
                }
            }
        }
    }

    #[tokio::test]
    async fn openocd_backend_drives_rsp_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(mock_rsp_server(listener));

        let mut backend = OpenOcdBackend::connect(&addr).await.expect("connect");
        assert_eq!(backend.kind(), BackendKind::OpenOcd);

        // Memory read: "m..,4" -> "deadbeef".
        let data = backend.read_bytes(0x2000_0000, 4).await.expect("read");
        assert_eq!(data, vec![0xde, 0xad, 0xbe, 0xef]);

        // Memory write: "M..:..." -> OK.
        backend
            .write_bytes(0x2000_0000, &[0x01, 0x02])
            .await
            .expect("write");

        // Register read: "pf" (r15/PC) -> little-endian 0x08000100.
        let pc = backend.core_reg(CoreRegId::Pc).await.expect("reg");
        assert_eq!(pc, 0x0800_0100);

        // Status: "?" -> T05 => Halted.
        assert_eq!(backend.status().await.unwrap(), CoreState::Halted);

        // Control via monitor (qRcmd) -> OK.
        backend.halt().await.expect("halt");
        backend.run().await.expect("run");

        // Breakpoints: Z1/z1 -> OK.
        backend
            .set_hw_breakpoint(0x0800_0100)
            .await
            .expect("set bp");
        backend
            .clear_hw_breakpoint(0x0800_0100)
            .await
            .expect("clear bp");

        drop(backend);
        let _ = server.await;
    }

    #[test]
    fn parses_openocd_reg_output() {
        // Real formats observed from openocd-esp32 on a live ESP32-S3.
        assert_eq!(parse_reg_value("pc (/32): 0x40381796\n"), Some(0x4038_1796));
        assert_eq!(parse_reg_value("a1 (/32): 0x3fcc67d0"), Some(0x3fcc_67d0));
        assert_eq!(parse_reg_value("no hex here"), None);
    }
}
