//! Enumerate nearby WiFi networks via the Windows WLAN API.
//!
//! `wlanapi.dll` exposes the same picker the system tray's "available
//! networks" popup uses. We don't try to drive a fresh scan (it'd be
//! async and only saves a few seconds); we just read whatever the OS
//! has cached, which refreshes every ~30s automatically.
//!
//! Each `WifiNetwork` is one SSID + encryption + signal — the API
//! collapses multi-BSSID networks, which is what a non-pentester
//! wants. Per-BSSID detail would require parsing the BSS list IE
//! blobs; not worth it for the LAN-survey use case.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WiFi::{
    WlanCloseHandle, WlanEnumInterfaces, WlanFreeMemory, WlanGetAvailableNetworkList,
    WlanOpenHandle, DOT11_AUTH_ALGO_80211_OPEN, DOT11_AUTH_ALGO_80211_SHARED_KEY,
    DOT11_AUTH_ALGO_RSNA, DOT11_AUTH_ALGO_RSNA_PSK, DOT11_AUTH_ALGO_WPA,
    DOT11_AUTH_ALGO_WPA3, DOT11_AUTH_ALGO_WPA3_SAE, DOT11_AUTH_ALGO_WPA_PSK,
    DOT11_AUTH_ALGORITHM, WLAN_AVAILABLE_NETWORK, WLAN_AVAILABLE_NETWORK_CONNECTED,
    WLAN_AVAILABLE_NETWORK_LIST, WLAN_INTERFACE_INFO_LIST,
};

#[derive(Debug, Clone)]
pub struct WifiNetwork {
    /// Network name. May be empty for hidden SSIDs (we keep those —
    /// it's interesting that they exist).
    pub ssid: String,
    /// 0..=100 quality, mapped roughly to dBm by Windows.
    pub signal_pct: u32,
    pub encryption: WifiEncryption,
    /// `true` if our system is currently connected to this network.
    pub connected: bool,
    /// `true` if the user has saved a profile for this network.
    pub saved_profile: bool,
    /// Name of the saved profile, if any. Often equal to the SSID
    /// but the user may have renamed it.
    pub profile_name: String,
}

/// Convert WLAN signal quality (0–100) to the approximate received
/// RSSI in dBm. Windows defines this mapping linearly: 0% = -100 dBm,
/// 100% = -50 dBm.
pub fn signal_quality_to_dbm(pct: u32) -> i32 {
    let p = pct.min(100) as i32;
    -100 + (p / 2)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiEncryption {
    Open,
    Wep,
    Wpa,
    Wpa2,
    Wpa3,
    Other,
}

impl WifiEncryption {
    pub fn label(self) -> &'static str {
        match self {
            WifiEncryption::Open  => "OPEN",
            WifiEncryption::Wep   => "WEP",
            WifiEncryption::Wpa   => "WPA",
            WifiEncryption::Wpa2  => "WPA2",
            WifiEncryption::Wpa3  => "WPA3",
            WifiEncryption::Other => "?",
        }
    }
}

/// Snapshot the WLAN API's cached scan results. Returns an empty vec
/// if the host has no WiFi adapter, the WLAN service isn't running,
/// or any of the underlying calls fails.
pub fn scan() -> Vec<WifiNetwork> {
    unsafe {
        let mut handle: HANDLE = HANDLE::default();
        let mut negotiated: u32 = 0;
        // ClientVersion 2 = WLAN 802.11 (Vista+); both Vista and
        // newer versions accept 2.
        let ret = WlanOpenHandle(2, None, &mut negotiated, &mut handle);
        if ret != 0 {
            return Vec::new();
        }

        let mut iface_list: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
        let ret = WlanEnumInterfaces(handle, None, &mut iface_list);
        if ret != 0 || iface_list.is_null() {
            let _ = WlanCloseHandle(handle, None);
            return Vec::new();
        }

        let mut out: Vec<WifiNetwork> = Vec::new();
        let n = (*iface_list).dwNumberOfItems as usize;
        let ifaces = std::slice::from_raw_parts((*iface_list).InterfaceInfo.as_ptr(), n);

        for iface in ifaces {
            let mut net_list: *mut WLAN_AVAILABLE_NETWORK_LIST = std::ptr::null_mut();
            // Flags = 0 → don't include hidden networks unless we have
            // a profile for them. That's the typical case and matches
            // what the system tray shows.
            let ret = WlanGetAvailableNetworkList(
                handle,
                &iface.InterfaceGuid,
                0,
                None,
                &mut net_list,
            );
            if ret != 0 || net_list.is_null() {
                continue;
            }
            let nn = (*net_list).dwNumberOfItems as usize;
            let nets = std::slice::from_raw_parts((*net_list).Network.as_ptr(), nn);
            for n in nets {
                out.push(convert_network(n));
            }
            WlanFreeMemory(net_list as *mut _);
        }

        WlanFreeMemory(iface_list as *mut _);
        let _ = WlanCloseHandle(handle, None);

        // Many networks appear once per saved profile (current,
        // alternate) — collapse by (SSID, encryption).
        out.sort_by(|a, b| b.signal_pct.cmp(&a.signal_pct));
        out.dedup_by(|a, b| a.ssid == b.ssid && a.encryption == b.encryption);
        out
    }
}

unsafe fn convert_network(n: &WLAN_AVAILABLE_NETWORK) -> WifiNetwork {
    let ssid_len = n.dot11Ssid.uSSIDLength.min(32) as usize;
    let ssid_bytes = &n.dot11Ssid.ucSSID[..ssid_len];
    let ssid = String::from_utf8_lossy(ssid_bytes).into_owned();

    let encryption = classify_auth(n.dot11DefaultAuthAlgorithm, n.bSecurityEnabled.as_bool());

    let connected = (n.dwFlags & WLAN_AVAILABLE_NETWORK_CONNECTED) != 0;
    // bit 2 = WLAN_AVAILABLE_NETWORK_HAS_PROFILE
    let saved_profile = (n.dwFlags & 2) != 0;

    let profile_name: String = {
        let end = n.strProfileName.iter().position(|&c| c == 0).unwrap_or(0);
        if end > 0 {
            OsString::from_wide(&n.strProfileName[..end])
                .into_string()
                .unwrap_or_default()
        } else {
            String::new()
        }
    };

    WifiNetwork {
        ssid,
        signal_pct: n.wlanSignalQuality,
        encryption,
        connected,
        saved_profile,
        profile_name,
    }
}

fn classify_auth(algo: DOT11_AUTH_ALGORITHM, security: bool) -> WifiEncryption {
    if !security {
        return WifiEncryption::Open;
    }
    if algo == DOT11_AUTH_ALGO_80211_OPEN || algo == DOT11_AUTH_ALGO_80211_SHARED_KEY {
        WifiEncryption::Wep
    } else if algo == DOT11_AUTH_ALGO_WPA || algo == DOT11_AUTH_ALGO_WPA_PSK {
        WifiEncryption::Wpa
    } else if algo == DOT11_AUTH_ALGO_RSNA || algo == DOT11_AUTH_ALGO_RSNA_PSK {
        WifiEncryption::Wpa2
    } else if algo == DOT11_AUTH_ALGO_WPA3 || algo == DOT11_AUTH_ALGO_WPA3_SAE {
        WifiEncryption::Wpa3
    } else {
        WifiEncryption::Other
    }
}
