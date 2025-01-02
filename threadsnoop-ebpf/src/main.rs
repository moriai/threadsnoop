#![no_std]
#![no_main]

use aya_ebpf::{macros::uprobe, programs::ProbeContext};
use aya_log_ebpf::info;

#[uprobe]
pub fn threadsnoop(ctx: ProbeContext) -> u32 {
    match try_threadsnoop(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_threadsnoop(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function pthread_create called by libc");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
