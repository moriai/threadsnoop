#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    macros::map,
    macros::uprobe,
    maps::PerfEventArray,
    programs::ProbeContext,
    helpers::bpf_get_current_pid_tgid,
    helpers::bpf_get_current_comm,
    helpers::gen::bpf_ktime_get_ns,
};
use threadsnoop_common::{ThreadFunc, ThreadInfo};

#[map]
static mut EVENTS: PerfEventArray<ThreadInfo> = PerfEventArray::<ThreadInfo>::new(0);

#[uprobe]
pub fn probe_pthread_create(ctx: ProbeContext) -> u32 {
    let target = ctx.arg(2).unwrap_or(0u64);
    match try_probe_pthread_func(ctx, target, ThreadFunc::Create) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uprobe]
pub fn probe_pthread_detach(ctx: ProbeContext) -> u32 {
    let target = ctx.arg(0).unwrap_or(0u64);
    match try_probe_pthread_func(ctx, target, ThreadFunc::Detach) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uprobe]
pub fn probe_pthread_exit(ctx: ProbeContext) -> u32 {
    match try_probe_pthread_func(ctx, 0, ThreadFunc::Exit) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uprobe]
pub fn probe_pthread_join(ctx: ProbeContext) -> u32 {
    let target = ctx.arg(0).unwrap_or(0u64);
    match try_probe_pthread_func(ctx, target, ThreadFunc::Join) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_probe_pthread_func(ctx: ProbeContext, target: u64, func: ThreadFunc) -> Result<u32, u32> {
    let ts = unsafe { bpf_ktime_get_ns() };
    let tid = bpf_get_current_pid_tgid() as u32;
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = bpf_get_current_comm().unwrap();

    let info = ThreadInfo { ts, pid, tid, comm, target, func};
    unsafe { EVENTS.output(&ctx, &info, 0) };

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
