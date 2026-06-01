//! Read-only snapshot of the machine's built-in Windows defenses —
//! Windows Defender, the Windows Firewall (per profile), UAC, and the
//! last successful Windows Update install. Used by the Summary view's
//! DEFENSES panel to give a non-analyst a one-glance "is my house in
//! order" indicator.
//!
//! Everything here goes through the registry rather than COM/WMI to
//! keep the surface tiny. The trade-off: tamper-protected newer state
//! (like Defender's tamper-protected real-time flag) isn't visible —
//! we fall back to "presence of MsMpEng.exe in our process table" as
//! a proxy. That's surfaced separately in the App layer.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use windows::core::PCWSTR;
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD,
    REG_SZ,
};

#[derive(Debug, Clone, Default)]
pub struct DefensesSnapshot {
    /// `True` if `MsMpEng.exe` (Defender's Antimalware Service
    /// Executable) is present in our live process table at snapshot
    /// time. Populated from the App side; we just hold the value.
    pub defender_process_seen: bool,

    /// Per-profile firewall state. `None` if we couldn't read the key.
    pub firewall_domain:  Option<bool>,
    pub firewall_private: Option<bool>,
    pub firewall_public:  Option<bool>,

    /// User Account Control enabled (1) vs disabled (0).
    pub uac_enabled: Option<bool>,

    /// String the Windows Update writes after a successful install.
    /// Format is `yyyy-MM-dd HH:mm:ss` in UTC. Left as a string so
    /// the UI can render it as-is.
    pub last_update_install: Option<String>,

    /// VPN status derived from the adapter list. We don't ask
    /// vendor-specific apps — we look for adapter descriptions that
    /// match known VPN client tunnel interfaces. Filled in from the
    /// App side so we don't need the network-inspect dependency here.
    pub vpn_status: VpnStatus,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum VpnStatus {
    /// VPN tunnel adapter present, up, and has an IP. `String` is the
    /// adapter description / vendor (e.g. "WireGuard").
    Active(String),
    /// Tunnel adapter is configured but currently down (no IP, OperStatus
    /// not Up). Means the client is installed but not connected.
    Inactive(String),
    /// No recognized VPN adapter present.
    #[default]
    None,
}

impl DefensesSnapshot {
    /// Pull everything readable from the registry. Cheap (~ms);
    /// fine to call on a 60-second timer.
    pub fn read() -> Self {
        let mut s = Self::default();

        s.firewall_domain  = read_reg_dword_bool(
            HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
            "EnableFirewall",
        );
        s.firewall_private = read_reg_dword_bool(
            HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
            "EnableFirewall",
        );
        s.firewall_public = read_reg_dword_bool(
            HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
            "EnableFirewall",
        );

        s.uac_enabled = read_reg_dword_bool(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA",
        );

        s.last_update_install = read_reg_string(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install",
            "LastSuccessTime",
        );

        s
    }

    /// Composite traffic-light: green if everything looks healthy,
    /// orange if anything is unset/unknown, red if any firewall profile
    /// is off, UAC is off, or Defender isn't running.
    pub fn health(&self) -> DefenseHealth {
        let any_red = self.firewall_domain  == Some(false)
                   || self.firewall_private == Some(false)
                   || self.firewall_public  == Some(false)
                   || self.uac_enabled      == Some(false)
                   || !self.defender_process_seen;
        if any_red {
            return DefenseHealth::Bad;
        }
        let any_unknown = self.firewall_domain.is_none()
            || self.firewall_private.is_none()
            || self.firewall_public.is_none()
            || self.uac_enabled.is_none();
        if any_unknown {
            DefenseHealth::Unknown
        } else {
            DefenseHealth::Good
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefenseHealth {
    Good,
    Unknown,
    Bad,
}

/// Classify an adapter description as a VPN tunnel client. Substring
/// match against a curated list of well-known vendors plus generic
/// "WireGuard"/"OpenVPN" markers. Returns the canonical vendor name
/// (for display) on match.
pub fn classify_vpn_adapter(description: &str) -> Option<&'static str> {
    let lc = description.to_ascii_lowercase();
    // Brand-specific first — they give nice display names.
    const PATTERNS: &[(&str, &str)] = &[
        ("wireguard",          "WireGuard"),
        ("wintun userspace",   "WireGuard"),
        ("openvpn",            "OpenVPN"),
        ("tap-windows",        "OpenVPN (TAP)"),
        ("nordlynx",           "NordVPN"),
        ("nordvpn",            "NordVPN"),
        ("expressvpn",         "ExpressVPN"),
        ("proton vpn",         "Proton VPN"),
        ("protonvpn",          "Proton VPN"),
        ("surfshark",          "Surfshark"),
        ("mullvad",            "Mullvad"),
        ("cyberghost",         "CyberGhost"),
        ("private internet",   "PIA"),
        ("ivpn",               "IVPN"),
        ("tunnelbear",         "TunnelBear"),
        ("windscribe",         "Windscribe"),
        ("cisco anyconnect",   "Cisco AnyConnect"),
        ("anyconnect",         "Cisco AnyConnect"),
        ("pulse secure",       "Pulse Secure"),
        ("globalprotect",      "Palo Alto GlobalProtect"),
        ("forticlient",        "FortiClient"),
        ("checkpoint",         "Check Point"),
        ("openconnect",        "OpenConnect"),
        ("zerotier",           "ZeroTier"),
        ("tailscale",          "Tailscale"),
        ("hamachi",            "Hamachi"),
    ];
    for (needle, name) in PATTERNS {
        if lc.contains(needle) {
            return Some(*name);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tiny registry helpers
// ---------------------------------------------------------------------------

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn read_reg_dword_bool(hive: HKEY, subkey: &str, value: &str) -> Option<bool> {
    read_reg_dword(hive, subkey, value).map(|v| v != 0)
}

fn read_reg_dword(hive: HKEY, subkey: &str, value: &str) -> Option<u32> {
    let subkey_w = to_wide(subkey);
    let value_w = to_wide(value);

    unsafe {
        let mut hk: HKEY = HKEY::default();
        let ret = RegOpenKeyExW(hive, PCWSTR(subkey_w.as_ptr()), 0, KEY_READ, &mut hk);
        if ret.0 != 0 {
            return None;
        }
        let mut ty = REG_DWORD;
        let mut buf = [0u8; 4];
        let mut sz: u32 = 4;
        let ret = RegQueryValueExW(
            hk,
            PCWSTR(value_w.as_ptr()),
            None,
            Some(&mut ty),
            Some(buf.as_mut_ptr()),
            Some(&mut sz),
        );
        let _ = RegCloseKey(hk);
        if ret.0 != 0 || ty != REG_DWORD {
            return None;
        }
        Some(u32::from_le_bytes(buf))
    }
}

fn read_reg_string(hive: HKEY, subkey: &str, value: &str) -> Option<String> {
    let subkey_w = to_wide(subkey);
    let value_w = to_wide(value);

    unsafe {
        let mut hk: HKEY = HKEY::default();
        let ret = RegOpenKeyExW(hive, PCWSTR(subkey_w.as_ptr()), 0, KEY_READ, &mut hk);
        if ret.0 != 0 {
            return None;
        }
        // Probe for size first.
        let mut ty = REG_SZ;
        let mut sz: u32 = 0;
        let ret = RegQueryValueExW(
            hk,
            PCWSTR(value_w.as_ptr()),
            None,
            Some(&mut ty),
            None,
            Some(&mut sz),
        );
        if ret.0 != 0 || ty != REG_SZ || sz == 0 {
            let _ = RegCloseKey(hk);
            return None;
        }
        let mut buf = vec![0u8; sz as usize];
        let mut sz2 = sz;
        let ret = RegQueryValueExW(
            hk,
            PCWSTR(value_w.as_ptr()),
            None,
            Some(&mut ty),
            Some(buf.as_mut_ptr()),
            Some(&mut sz2),
        );
        let _ = RegCloseKey(hk);
        if ret.0 != 0 {
            return None;
        }
        // Reg strings are UTF-16 LE, sometimes null-terminated.
        let u16s: Vec<u16> = buf
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        OsString::from_wide(&u16s).into_string().ok()
    }
}
