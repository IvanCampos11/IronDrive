pub mod crypto;
pub mod mime;
pub mod path_safety;

/// Format a byte count as a human-readable string using binary units (e.g. "50 GiB", "8 MiB").
pub fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;

    if bytes >= TIB && bytes % TIB == 0 {
        format!("{} TiB", bytes / TIB)
    } else if bytes >= GIB && bytes % GIB == 0 {
        format!("{} GiB", bytes / GIB)
    } else if bytes >= MIB && bytes % MIB == 0 {
        format!("{} MiB", bytes / MIB)
    } else if bytes >= KIB && bytes % KIB == 0 {
        format!("{} KiB", bytes / KIB)
    } else {
        format!("{} B", bytes)
    }
}
