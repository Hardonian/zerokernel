#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns,
    },
    macros::{map, tracepoint, xdp},
    maps::RingBuf,
    programs::{TracePointContext, XdpContext},
};
use zerokernel_common::{
    FLAG_ROOT_PRIVILEGE, HOOK_TRACEPOINT_EXECVE, HOOK_XDP_IPV4_PACKET, KernelSyscallEvent,
};

#[map]
static AUDIT_RINGBUF: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    let _ = try_capture_syscall(ctx, 59);
    0
}

#[xdp]
pub fn zerokernel_xdp_firewall(ctx: XdpContext) -> u32 {
    match try_inspect_xdp(&ctx) {
        Ok(action) => action,
        Err(()) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_capture_syscall(_ctx: TracePointContext, syscall_nr: u32) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid & 0xFFFF_FFFF) as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    if let Some(mut entry) = AUDIT_RINGBUF.reserve::<KernelSyscallEvent>(0) {
        let mut flags = HOOK_TRACEPOINT_EXECVE;
        if uid == 0 {
            flags |= FLAG_ROOT_PRIVILEGE;
        }
        entry.write(KernelSyscallEvent {
            timestamp_ns,
            pid,
            tgid,
            uid,
            syscall_nr,
            target_ipv4: 0,
            target_port: 0,
            flags,
            comm,
        });
        entry.submit(0);
    }
    Ok(0)
}

#[inline(always)]
fn try_inspect_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    if data + 34 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth_proto = u16::from_be(unsafe { *((data + 12) as *const u16) });
    if eth_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_header = data + 14;
    let protocol = unsafe { *((ip_header + 9) as *const u8) };
    let dst_ip = u32::from_be(unsafe { *((ip_header + 16) as *const u32) });

    let mut dst_port: u16 = 0;
    if protocol == IPPROTO_TCP && ip_header + 24 <= data_end {
        dst_port = u16::from_be(unsafe { *((ip_header + 22) as *const u16) });
    }

    let timestamp_ns = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = AUDIT_RINGBUF.reserve::<KernelSyscallEvent>(0) {
        entry.write(KernelSyscallEvent {
            timestamp_ns,
            pid: 0,
            tgid: 0,
            uid: 1000,
            syscall_nr: 42,
            target_ipv4: dst_ip,
            target_port: dst_port,
            flags: HOOK_XDP_IPV4_PACKET,
            comm: *b"xdp-wire-frame\0\0",
        });
        entry.submit(0);
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}