//! Which cores exist, and how to ask the OS for one.

use std::sync::OnceLock;

/// Worker counts for the pool: performance cores first, then the efficiency
/// cores that join the same work queue at a lower scheduling class.
#[derive(Clone, Copy, Debug)]
pub struct Topology {
    /// Workers scheduled on performance cores, including the dispatcher.
    pub perf: usize,
    /// Extra workers scheduled on efficiency cores; `0` on a homogeneous host.
    pub efficiency: usize,
}

impl Topology {
    /// Total workers, dispatcher included.
    #[must_use]
    pub const fn total(self) -> usize {
        self.perf + self.efficiency
    }
}

/// The pool's shape, resolved once.
///
/// `LEANVM_NUM_PERFORMANCE_THREADS` and `LEANVM_NUM_EFFICIENCY_THREADS` set each
/// cluster independently. `LEANVM_NUM_THREADS` and `RAYON_NUM_THREADS` remain
/// aliases for the performance-worker count and retain the detected efficiency
/// workers. A legacy value of `1` means strictly sequential.
#[must_use]
pub fn topology() -> Topology {
    static TOPOLOGY: OnceLock<Topology> = OnceLock::new();
    *TOPOLOGY.get_or_init(|| {
        let explicit_perf = std::env::var("LEANVM_NUM_PERFORMANCE_THREADS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|&value| value > 0);
        let explicit_efficiency = std::env::var("LEANVM_NUM_EFFICIENCY_THREADS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok());
        let legacy_perf = ["LEANVM_NUM_THREADS", "RAYON_NUM_THREADS"]
            .iter()
            .find_map(|key| std::env::var(key).ok())
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n > 0);
        resolve_topology(explicit_perf, explicit_efficiency, legacy_perf, default_topology())
    })
}

fn resolve_topology(
    explicit_perf: Option<usize>,
    explicit_efficiency: Option<usize>,
    legacy_perf: Option<usize>,
    detected: Topology,
) -> Topology {
    if explicit_perf.is_some() || explicit_efficiency.is_some() {
        return Topology {
            perf: explicit_perf.unwrap_or(detected.perf).max(1),
            efficiency: explicit_efficiency.unwrap_or(detected.efficiency),
        };
    }
    match legacy_perf {
        Some(1) => Topology { perf: 1, efficiency: 0 },
        Some(perf) => Topology {
            perf,
            efficiency: detected.efficiency,
        },
        None => detected,
    }
}

/// Worker count including the dispatcher.
#[must_use]
#[inline]
pub fn num_threads() -> usize {
    topology().total()
}

/// The pool's shape when nothing is pinned.
///
/// One performance worker is held back **when there are efficiency workers to
/// absorb the slack**, i.e. on Apple silicon. The prover does not run alone on
/// the fast cluster: `cpu::prove` warms the BLAKE2s setup on a background thread,
/// and the OS wants a core. Saturating the cluster means any interference
/// deschedules a worker mid-dispatch, and every barrier then waits for it.
///
/// Measured at the 820-signature XMSS workload, M4 Max (12 P + 4 E):
/// 11 performance workers prove in 1.373 s, 12 in 1.578 s, a 13% penalty for
/// using one more core. On a homogeneous 16-thread Zen 4 host the same
/// reservation is a wash (4.331 s vs 4.319 s, inside the ±0.5% interval): there
/// are no efficiency workers to take over the reserved core's share, so the
/// barrier-jitter win and the lost core cancel. Hence the condition is "are there
/// efficiency workers", not a fixed count.
fn default_topology() -> Topology {
    let efficiency = efficiency_cores();
    let perf = perf_cores();
    // Never reserve below two performance workers.
    let reserve = usize::from(efficiency > 0 && perf > 2);
    Topology {
        perf: perf - reserve,
        efficiency,
    }
}

/// Performance-core count: `hw.perflevel0.logicalcpu` on Apple silicon (where
/// `available_parallelism` counts the efficiency cores too, and those are handled
/// separately), else the platform's parallelism.
fn perf_cores() -> usize {
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    if let Some(n) = sysctl_usize(c"hw.perflevel0.logicalcpu") {
        return n;
    }
    std::thread::available_parallelism().map_or(1, |n| n.get())
}

/// Efficiency-core count on Apple silicon, else `0`.
fn efficiency_cores() -> usize {
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    if let Some(n) = sysctl_usize(c"hw.perflevel1.logicalcpu") {
        return n;
    }
    0
}

/// Read an integer `sysctl` by name through the syscall, never a spawned
/// `sysctl` process. Any failure reads as "unknown".
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
fn sysctl_usize(name: &core::ffi::CStr) -> Option<usize> {
    let mut value: i32 = 0;
    let mut len = core::mem::size_of::<i32>();
    // SAFETY: a read-only sysctl; `value`/`len` are correctly sized and the
    // new-value pointer is null, so nothing is written into the kernel.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&raw mut value).cast(),
            &raw mut len,
            core::ptr::null_mut(),
            0,
        )
    };
    (rc == 0 && len == core::mem::size_of::<i32>() && value > 0).then_some(value as usize)
}

/// Scheduling class for a worker, which on Apple silicon is also a choice of
/// core cluster: the scheduler keeps `USER_INTERACTIVE` work off the efficiency
/// cores and places `UTILITY` work on them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Qos {
    /// Latency-critical: performance cores.
    Interactive,
    /// Background-ish: efficiency cores.
    Utility,
}

/// Tag the calling thread with `qos`. Best-effort, since QoS is a scheduling hint
/// and a failure must not affect correctness, only placement. No-op off macOS.
pub(crate) fn set_qos(qos: Qos) {
    #[cfg(target_os = "macos")]
    {
        const QOS_CLASS_USER_INTERACTIVE: u32 = 0x21;
        const QOS_CLASS_UTILITY: u32 = 0x11;
        unsafe extern "C" {
            fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
        }
        let class = match qos {
            Qos::Interactive => QOS_CLASS_USER_INTERACTIVE,
            Qos::Utility => QOS_CLASS_UTILITY,
        };
        // SAFETY: a libSystem call that only adjusts this thread's scheduling class.
        unsafe {
            let _ = pthread_set_qos_class_self_np(class, 0);
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = qos;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DETECTED: Topology = Topology { perf: 8, efficiency: 4 };

    #[test]
    fn explicit_cluster_limits_are_independent() {
        assert_eq!(resolve_topology(Some(4), Some(0), None, DETECTED).perf, 4);
        assert_eq!(resolve_topology(Some(4), Some(0), None, DETECTED).efficiency, 0);
        assert_eq!(resolve_topology(Some(4), Some(2), None, DETECTED).total(), 6);
    }

    #[test]
    fn legacy_single_thread_remains_sequential() {
        assert_eq!(resolve_topology(None, None, Some(1), DETECTED).total(), 1);
    }

    #[test]
    fn legacy_performance_limit_retains_detected_efficiency_workers() {
        let topology = resolve_topology(None, None, Some(4), DETECTED);
        assert_eq!(topology.perf, 4);
        assert_eq!(topology.efficiency, 4);
    }
}
