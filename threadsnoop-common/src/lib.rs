#![no_std]

#[repr(C)]
pub struct ThreadInfo {
    pub ts: u64,        // Timestamp
    pub pid: u32,       // Process ID
    pub tid: u32,       // Thread ID
    pub entry: u64,     // Thread entry address
    pub comm: [u8; 16], // Command Name
}
