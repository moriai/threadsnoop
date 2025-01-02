#![no_std]

pub enum ThreadFunc {
    Create, Detach, Exit, Join,
}

#[cfg(feature = "user")]
impl ThreadFunc {
    pub fn name(self) -> &'static str {
        match self {
            ThreadFunc::Create  => "create",
            ThreadFunc::Detach  => "detach",
            ThreadFunc::Exit    => "exit",
            ThreadFunc::Join    => "join",
        }
    }
}

#[repr(C)]
pub struct ThreadInfo {
    pub ts: u64,            // Timestamp
    pub pid: u32,           // Process ID
    pub tid: u32,           // Thread ID
    pub comm: [u8; 16],     // Command Name
    pub target: u64,        // Target thread
    pub func: ThreadFunc,   // Thread function
}
