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
    FLAG_ROOT_PRIVILEGE, HOOK_SCHED_PROCESS_EXIT, HOOK_SCHED_PROCESS_FORK,
    HOOK_TRACEPOINT_CONNECT, HOOK_TRACEPOINT_EXECVE, HOOK_TRACEPOINT_OPENAT,
    HOOK_TRACEPOINT_SETUID, HOOK_XDP_IPV4_PACKET, HOOK_XDP_IPV6_PACKET, KernelSyscallEvent,
};

#[map]
static AUDIT_RINGBUF: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    let _ = try_capture_syscall(ctx, 59, HOOK_TRACEPOINT_EXECVE, 0, 0);
    0
}

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    let _ = try_capture_syscall(ctx, 257, HOOK_TRACEPOINT_OPENAT, 0, 0);
    0
}

#[tracepoint]
pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    let _ = try_capture_syscall(ctx, 42, HOOK_TRACEPOINT_CONNECT, 0, 0);
    0
}

#[tracepoint]
pub fn sys_enter_setuid(ctx: TracePointContext) -> u32 {
    let _ = try_capture_syscall(ctx, 105, HOOK_TRACEPOINT_SETUID, 0, 0);
    0
}

#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    let _ = try_capture_syscall(ctx, 56, HOOK_SCHED_PROCESS_FORK, 0, 0);
    0
}

#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    let _ = try_capture_syscall(ctx, 60, HOOK_SCHED_PROCESS_EXIT, 0, 0);
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
fn try_capture_syscall(
    _ctx: TracePointContext,
    syscall_nr: u32,
    hook_id: u16,
    target_ipv4: u32,
    target_port: u16,
) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid & 0xFFFF_FFFF) as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    if let Some(mut entry) = AUDIT_RINGBUF.reserve::<KernelSyscallEvent>(0) {
        let mut flags = hook_id;
        if uid == 0 {
            flags |= FLAG_ROOT_PRIVILEGE;
        }
        entry.write(KernelSyscallEvent {
            timestamp_ns,
            pid,
            tgid,
            uid,
            syscall_nr,
            target_ipv4,
            target_port,
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

    if data + 14 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth_proto = u16::from_be(unsafe { *((data + 12) as *const u16) });

    if eth_proto == ETH_P_IP {
        if data + 34 > data_end {
            return Ok(xdp_action::XDP_PASS);
        }

        let ip_header = data + 14;
        let protocol = unsafe { *((ip_header + 9) as *const u8) };
        let dst_ip = u32::from_be(unsafe { *((ip_header + 16) as *const u32) });

        let mut dst_port: u16 = 0;
        if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) && ip_header + 24 <= data_end {
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
                comm: *b"xdp-ipv4-frame\0\0",
            });
            entry.submit(0);
        }
    } else if eth_proto == ETH_P_IPV6 {
        if data + 54 > data_end {
            return Ok(xdp_action::XDP_PASS);
        }

        let ip6_header = data + 14;
        let next_hdr = unsafe { *((ip6_header + 6) as *const u8) };

        let mut dst_port: u16 = 0;
        if (next_hdr == IPPROTO_TCP || next_hdr == IPPROTO_UDP) && ip6_header + 44 <= data_end {
            dst_port = u16::from_be(unsafe { *((ip6_header + 42) as *const u16) });
        }

        let timestamp_ns = unsafe { bpf_ktime_get_ns() };
        if let Some(mut entry) = AUDIT_RINGBUF.reserve::<KernelSyscallEvent>(0) {
            entry.write(KernelSyscallEvent {
                timestamp_ns,
                pid: 0,
                tgid: 0,
                uid: 1000,
                syscall_nr: 42,
                target_ipv4: 0,
                target_port: dst_port,
                flags: HOOK_XDP_IPV6_PACKET,
                comm: *b"xdp-ipv6-frame\0\0",
            });
            entry.submit(0);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
