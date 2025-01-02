use aya::{
    maps::perf::AsyncPerfEventArray,
    programs::UProbe,
    util::online_cpus,
};
use bytes::BytesMut;
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use threadsnoop_common::ThreadInfo;
use tokio::{task,signal};
const SEC_NSEC: u64 = 1_000_000_000;

fn gettime() -> u64 {
    let mut time = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_COARSE, &mut time) };
    assert!(ret == 0);
    (time.tv_sec as u64) * SEC_NSEC + time.tv_nsec as u64
}

#[derive(Debug, Parser)]
#[command(author, version)]
struct Opt {
    #[clap(short, long, help = "Attach to the process with <PID>")]
    pid: Option<i32>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/threadsnoop"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let Opt { pid } = opt;

    let program_0: &mut UProbe = ebpf.program_mut("probe_pthread_create").unwrap().try_into()?;
    program_0.load()?;
    program_0.attach(Some("pthread_create"), 0, "/lib/x86_64-linux-gnu/libc.so.6", pid)?;

    let program_1: &mut UProbe = ebpf.program_mut("probe_pthread_detach").unwrap().try_into()?;
    program_1.load()?;
    program_1.attach(Some("pthread_detach"), 0, "/lib/x86_64-linux-gnu/libc.so.6", pid)?;

    let program_2: &mut UProbe = ebpf.program_mut("probe_pthread_exit").unwrap().try_into()?;
    program_2.load()?;
    program_2.attach(Some("pthread_exit"), 0, "/lib/x86_64-linux-gnu/libc.so.6", pid)?;

    let program_3: &mut UProbe = ebpf.program_mut("probe_pthread_join").unwrap().try_into()?;
    program_3.load()?;
    program_3.attach(Some("pthread_join"), 0, "/lib/x86_64-linux-gnu/libc.so.6", pid)?;

    let start = gettime();
    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");

    let mut perf_array = AsyncPerfEventArray::try_from(ebpf.take_map("EVENTS").unwrap())?;

    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const ThreadInfo;
                    let data = unsafe { ptr.read_unaligned() };
                    let comm = data.comm.iter().filter(|&s| *s != 0u8).map(|&s| s as char).collect::<String>();
                    let dt = data.ts - start;
                    let sec = dt / SEC_NSEC;
                    let nsec = dt - sec * SEC_NSEC;
                    println!("{:3}.{:09} {:7} {:7} {:16} {:6} 0x{:x}",
                        sec, nsec, data.pid, data.tid, comm, data.func.name(), data.target);
                }
            }
        });
    }

    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
