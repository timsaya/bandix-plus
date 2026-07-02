use crate::api::{ApiState, start_server};
use crate::ebpf::shared::load_ebpf_programs;
use crate::monitor::{CompletedAggregate, HistogramHistory, MonitorRuntime, TrafficHistory, build_recovered_snapshot, collect_snapshot};
use crate::options::{Options, TcBackend, TcOrder};
use crate::persistence::PersistenceManager;
use crate::policy::{apply_runtime_policy, collect_observed_pairs, init_runtime, log_policy_runtime_summary, parse_policy};
use crate::topology::TopologySnapshot;
use crate::utils::system_utils::{check_interface_exist, redact_ipv6_cidr_for_log};
use crate::utils::time_utils;
use log::LevelFilter;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// 主入口：初始化日志、校验参数并启动监控服务。
pub async fn run(options: Options) -> anyhow::Result<()> {
    validate_arguments(&options)?;

    let log_level = match options.log_level.to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => {
            return Err(anyhow::anyhow!(
                "Invalid log level: {}. Valid values: trace, debug, info, warn, error",
                options.log_level
            ));
        }
    };

    env_logger::Builder::new()
        .filter(None, log_level)
        .filter_module("aya::bpf", LevelFilter::Error)
        .target(env_logger::Target::Stdout)
        .init();

    if !options.enable_traffic {
        log::warn!("traffic collector disabled (--enable-traffic=false); exiting without starting services");
        return Ok(());
    }

    // 运行服务
    run_service(&options).await?;

    Ok(())
}

/// 加载 eBPF、拓扑与策略，启动采集循环与 API 服务。
async fn run_service(options: &Options) -> anyhow::Result<()> {
    let topology = TopologySnapshot::discover()?;
    let persistence = Arc::new(PersistenceManager::new(&options.data_dir)?);

    log::info!("interfaces for monitoring:");
    for iface in topology.interfaces() {
        let ipv6_for_log: Vec<String> = iface.ipv6_cidrs.iter().map(|s| redact_ipv6_cidr_for_log(s)).collect();
        log::info!(
            "ifindex={} name={} role={:?} zone={:?} parent_ifindex={:?} ipv4_subnets={:?} ipv6_subnets={:?}",
            iface.ifindex,
            iface.name,
            iface.role,
            iface.zone,
            iface.parent_ifindex,
            iface.ipv4_cidrs,
            ipv6_for_log
        );
    }
    log::info!("persistence data dir={}", persistence.data_dir().display());
    log::info!("traffic persistence enabled={}", options.traffic_enable_storage);
    log::info!("traffic persist interval={}s", options.traffic_flush_interval);

    let policy = parse_policy();

    let mut policy_runtime_raw = init_runtime(policy);
    if let Err(e) = persistence.load_policy_runtime(&mut policy_runtime_raw, &topology) {
        log::warn!("load policy state failed: {}", e);
    }
    log_policy_runtime_summary(&policy_runtime_raw);
    let policy_runtime = Arc::new(RwLock::new(policy_runtime_raw));
    let topology_state = Arc::new(RwLock::new(topology.clone()));

    let mut monitor_runtime = MonitorRuntime::default();
    if let Err(e) = persistence.load_monitor_runtime(&mut monitor_runtime, &topology) {
        log::warn!("load devices state failed: {}", e);
    }
    log::info!("devices.loaded known_devices={}", monitor_runtime.device_registry.entries.len());

    let collect_interval_secs = 1_u64;
    let history_points = ((options.history_window_minutes as u64) * 60).max(1) as usize;
    let history = Arc::new(RwLock::new(TrafficHistory::new(history_points)));

    let mut histogram_raw = HistogramHistory::new();
    if options.traffic_enable_storage {
        if let Err(e) = persistence.load_histogram(&topology, &mut histogram_raw) {
            log::warn!("load traffic histogram state failed: {}", e);
        }
    }
    let recovery_now_ms = time_utils::now_millis();
    if options.traffic_enable_storage {
        if let Err(e) = persistence.load_current_hour_histogram(&topology, &mut histogram_raw, recovery_now_ms) {
            log::warn!("load current-hour histogram state failed: {}", e);
        }
    }
    let (ring_iface_cumulative, ring_device_cumulative) = histogram_raw.cumulative_from_all();
    monitor_runtime.cumulative_iface = ring_iface_cumulative;
    monitor_runtime.cumulative_device = ring_device_cumulative;

    let monitor_runtime = Arc::new(RwLock::new(monitor_runtime));
    let recovered_snapshot = {
        let runtime_guard = monitor_runtime.read().await;
        build_recovered_snapshot(&runtime_guard, &topology)
    };
    let snapshot = Arc::new(RwLock::new(recovered_snapshot));
    let histogram = Arc::new(RwLock::new(histogram_raw));
    let monitor_ifaces = options.iface.clone();
    let api_state = ApiState {
        snapshot: Arc::clone(&snapshot),
        history: Arc::clone(&history),
        histogram: Arc::clone(&histogram),
        monitor_runtime: Arc::clone(&monitor_runtime),
        policy_runtime: Arc::clone(&policy_runtime),
        topology: Arc::clone(&topology_state),
        persistence: Some(Arc::clone(&persistence)),
        traffic_enable_storage: options.traffic_enable_storage,
    };

    // 解析 TC 后端/顺序并加载 eBPF 实例
    let tc_backend = TcBackend::parse(&options.tc_backend).unwrap();
    let tc_order = TcOrder::parse(&options.tc_order).unwrap();
    let ebpf = load_ebpf_programs(
        &options.iface,
        tc_backend,
        tc_order,
        options.netlink_priority,
        options.tcx_anchor_ingress_id,
        options.tcx_anchor_egress_id,
    )?;

    let collect_interval = Duration::from_secs(collect_interval_secs);
    let mut collector_ebpf = ebpf;
    let collector_topology = Arc::clone(&topology_state);
    let collector_snapshot = Arc::clone(&snapshot);
    let collector_history = Arc::clone(&history);
    let collector_histogram = Arc::clone(&histogram);
    let collector_monitor_runtime = Arc::clone(&monitor_runtime);
    let collector_policy_runtime = Arc::clone(&policy_runtime);
    let collector_monitor_ifaces = monitor_ifaces;
    let collector_persistence = Arc::clone(&persistence);
    let collector_traffic_enable_storage = options.traffic_enable_storage;
    let periodic_persist_interval_ms = options.traffic_flush_interval.saturating_mul(1000);
    tokio::spawn(async move {
        let mut last_periodic_persist_ms = 0u64;
        let mut ticker = tokio::time::interval(collect_interval);
        loop {
            ticker.tick().await;
            let observed_pairs = collect_observed_pairs(&mut collector_ebpf).unwrap_or_default();
            {
                let topology_guard = collector_topology.read().await;
                let guard = collector_policy_runtime.read().await;
                if let Err(e) = apply_runtime_policy(
                    &mut collector_ebpf,
                    &guard,
                    &observed_pairs,
                    &topology_guard,
                    time_utils::now_millis(),
                ) {
                    log::error!("apply runtime policy failed: {}", e);
                }
            }
            let result = {
                let topology_guard = collector_topology.read().await;
                let mut runtime_guard = collector_monitor_runtime.write().await;
                collect_snapshot(
                    &mut collector_ebpf,
                    &topology_guard,
                    &mut runtime_guard,
                    collect_interval,
                    &collector_monitor_ifaces,
                )
            };
            match result {
                Ok(data) => {
                    {
                        let mut history_guard = collector_history.write().await;
                        history_guard.ingest_snapshot(&data);
                    }
                    let completed = {
                        let mut histogram_guard = collector_histogram.write().await;
                        histogram_guard.ingest_snapshot_collect_completed(&data)
                    };
                    if collector_traffic_enable_storage {
                        for item in completed {
                            match item {
                                CompletedAggregate::Iface { iface, bucket } => {
                                    if let Err(e) = collector_persistence.append_iface_bucket(&iface, &bucket) {
                                        log::error!("persist iface ring failed iface={} err={}", iface, e);
                                    }
                                }
                                CompletedAggregate::Device { iface, mac, bucket } => {
                                    if let Err(e) = collector_persistence.append_device_bucket(&iface, &mac, &bucket) {
                                        log::error!("persist device ring failed iface={} mac={} err={}", iface, mac, e);
                                    }
                                }
                            }
                        }
                    }
                    {
                        let mut guard = collector_snapshot.write().await;
                        *guard = data.clone();
                    }

                    if data.timestamp_ms.saturating_sub(last_periodic_persist_ms) >= periodic_persist_interval_ms {
                        let topo = collector_topology.read().await.clone();
                        let runtime_saved = {
                            let runtime_guard = collector_monitor_runtime.read().await;
                            match collector_persistence.save_monitor_runtime(&runtime_guard, &topo) {
                                Ok(_) => true,
                                Err(e) => {
                                    log::error!("persist devices state failed: {}", e);
                                    false
                                }
                            }
                        };

                        let histogram_saved = if collector_traffic_enable_storage {
                            let histogram_guard = collector_histogram.read().await;
                            match collector_persistence.save_current_hour_histogram(&histogram_guard, &topo) {
                                Ok(_) => true,
                                Err(e) => {
                                    log::error!("persist current-hour state failed: {}", e);
                                    false
                                }
                            }
                        } else {
                            true
                        };

                        if runtime_saved && histogram_saved {
                            last_periodic_persist_ms = data.timestamp_ms;
                        }
                    }
                }
                Err(e) => {
                    log::error!("collector loop error: {}", e);
                }
            }
        }
    });

    let bind_addr = format!("{}:{}", options.host, options.port);
    log::info!("API server listening on {}", bind_addr);
    start_server(&bind_addr, api_state).await?;

    Ok(())
}

/// 校验 --iface 和 TC 相关参数。
fn validate_arguments(options: &Options) -> anyhow::Result<()> {
    if options.enable_traffic {
        if options.iface.is_empty() {
            anyhow::bail!("at least one --iface is required when --enable-traffic=true");
        }

        // 检查网络接口是否存在
        check_interface_exist(&options.iface)?;

        // 检查 tc_order 参数是否合法
        let tc_order = TcOrder::parse(&options.tc_order).ok_or_else(|| {
            anyhow::anyhow!(
                "Invalid tc-order: {}. Valid: first, default, last, before, after",
                options.tc_order
            )
        })?;

        // 检查 tc_backend 参数是否合法
        let tc_backend = TcBackend::parse(&options.tc_backend)
            .ok_or_else(|| anyhow::anyhow!("Invalid tc-backend: {}. Valid: auto, tcx, netlink", options.tc_backend))?;
        if options.netlink_priority.is_some() && tc_backend == TcBackend::Tcx {
            anyhow::bail!("--netlink-priority cannot be used with --tc-backend=tcx");
        }

        match tc_order {
            TcOrder::Before | TcOrder::After => {
                let has_ingress = options.tcx_anchor_ingress_id.is_some();
                let has_egress = options.tcx_anchor_egress_id.is_some();
                if !has_ingress && !has_egress {
                    anyhow::bail!(
                        "anchor program id is required when --tc-order is before/after; use --tcx-anchor-ingress-id/--tcx-anchor-egress-id"
                    );
                }
                if tc_backend == TcBackend::Netlink {
                    anyhow::bail!("--tc-order=before/after is only supported with tcx backend");
                }
            }
            _ => {
                if options.tcx_anchor_ingress_id.is_some() || options.tcx_anchor_egress_id.is_some() {
                    anyhow::bail!("--tcx-anchor-ingress-id and --tcx-anchor-egress-id can only be used when --tc-order is before/after");
                }
            }
        }
    }

    if options.host.trim().is_empty() {
        anyhow::bail!("--host cannot be empty");
    }
    if options.traffic_flush_interval == 0 {
        anyhow::bail!("--traffic_flush_interval must be greater than 0");
    }

    Ok(())
}
