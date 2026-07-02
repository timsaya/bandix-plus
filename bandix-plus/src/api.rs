use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use chrono::{Datelike, Duration as ChronoDuration, Local, TimeZone};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};

use crate::monitor::{
    AggregateBucket, AggregatedBucket, HistogramHistory, HistoryDirection, HistorySample, HistoryTrafficType, KnownDevice, MonitorRuntime,
    SnapshotData, TrafficHistory,
};
use crate::persistence::PersistenceManager;
use crate::policy::{
    CreateScheduledRuleRequest, GuestDefaultRateLimitApi, GuestWhitelistEntryApi, GuestWhitelistEntryRequest, InterfaceRateLimitApi,
    PolicyItem, PolicyRuntime, ScheduledRuleApi, SetInterfaceRateLimitRequest, UpdateScheduledRuleRequest, add_guest_whitelist,
    create_scheduled_rule, delete_guest_default, delete_iface_limit, delete_scheduled_rule, get_guest_defaults, get_guest_whitelist,
    get_iface_limits, get_scheduled_rules, policy_items, remove_guest_whitelist, set_guest_default, set_guest_default_enabled,
    set_iface_limit, update_scheduled_rule,
};
use crate::topology::TopologySnapshot;
use crate::utils::mac_utils;

#[derive(Clone)]
pub struct ApiState {
    pub snapshot: Arc<RwLock<SnapshotData>>,
    pub history: Arc<RwLock<TrafficHistory>>,
    pub histogram: Arc<RwLock<HistogramHistory>>,
    pub monitor_runtime: Arc<RwLock<MonitorRuntime>>,
    pub policy_runtime: Arc<RwLock<PolicyRuntime>>,
    pub topology: Arc<RwLock<TopologySnapshot>>,
    pub persistence: Option<Arc<PersistenceManager>>,
    pub traffic_enable_storage: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct DevicesQuery {
    pub iface: Option<String>,
    pub period: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct OverviewQuery {
    pub period: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SetDeviceHostnameRequest {
    pub iface: String,
    pub mac: String,
    pub hostname: String,
}

#[derive(Debug, Deserialize)]
pub struct SetEnabledRequest {
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct HistoryQuery {
    /// 内核网卡名（如 `eth0`），与 `/api/overview` 的 `ifname` 一致；服务端解析为 ifindex。
    pub iface: Option<String>,
    pub mac: Option<String>,
    pub traffic_type: Option<String>,
    pub direction: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct AggregateQuery {
    /// 内核网卡名；服务端解析为 ifindex。
    pub iface: Option<String>,
    pub mac: Option<String>,
    /// 与 `/api/trend` 相同：`all` / `ipv4` / `ipv6`；响应中另一侧字节与 bps 统计置零。
    pub traffic_type: Option<String>,
    pub start_ms: Option<u64>,
    pub end_ms: Option<u64>,
    pub bucket: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct UsageRankingQuery {
    /// 内核网卡名；服务端解析为 ifindex。
    pub iface: Option<String>,
    /// 与 `/api/trend` 相同：`all` / `ipv4` / `ipv6`。
    pub traffic_type: Option<String>,
    pub start_ms: Option<u64>,
    pub end_ms: Option<u64>,
    /// 返回条目数；`0` 表示不限制。
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageRankingItem {
    pub iface: String,
    pub mac: String,
    pub hostname: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub up_bytes: u64,
    pub down_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiEnvelope<T> {
    pub ok: bool,
    pub data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn router(state: ApiState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers(Any);

    Router::new()
        .route("/api/health", get(health))
        .route("/api/snapshot", get(snapshot))
        .route("/api/overview", get(overview))
        .route("/api/devices", get(devices))
        .route("/api/devices/hostname", put(set_device_hostname_handler))
        .route("/api/trend", get(history))
        .route("/api/histogram", get(aggregate))
        .route("/api/usage_ranking", get(usage_ranking))
        .route("/api/traffic/persist", post(persist_traffic))
        .route("/api/policy", get(policy))
        .route("/api/rate_limit/schedules", get(get_schedules).post(create_schedule))
        .route(
            "/api/rate_limit/schedules/{id}",
            put(update_schedule).patch(update_schedule).delete(delete_schedule),
        )
        .route(
            "/api/rate_limit/iface_limits",
            get(get_iface_limits_handler).post(set_iface_limit_handler),
        )
        .route("/api/rate_limit/iface_limits/{iface}", delete(delete_iface_limit_handler))
        .route(
            "/api/rate_limit/guest_defaults",
            get(get_guest_defaults_handler).post(set_guest_default_handler),
        )
        .route("/api/rate_limit/guest_defaults/{iface}", delete(delete_guest_default_handler))
        .route(
            "/api/rate_limit/guest_defaults/{iface}/enable",
            put(set_guest_default_enable_handler),
        )
        .route(
            "/api/rate_limit/guest_whitelist",
            get(get_guest_whitelist_handler)
                .post(add_guest_whitelist_handler)
                .delete(remove_guest_whitelist_handler),
        )
        .with_state(state)
        .layer(cors)
}

async fn usage_ranking(
    State(state): State<ApiState>,
    Query(q): Query<UsageRankingQuery>,
) -> Result<Json<ApiEnvelope<Vec<UsageRankingItem>>>, StatusCode> {
    let Some(iface) = q.iface.clone().filter(|s| !s.trim().is_empty()) else {
        return Err(StatusCode::BAD_REQUEST);
    };

    let tt = parse_traffic_type(q.traffic_type.as_deref());

    let now_ms = Local::now().timestamp_millis() as u64;
    let default_start = (Local::now() - ChronoDuration::days(365)).timestamp_millis() as u64;
    let start_ms = q.start_ms.unwrap_or(default_start);
    let end_ms = q.end_ms.unwrap_or(now_ms);
    if end_ms < start_ms {
        return Err(StatusCode::BAD_REQUEST);
    }

    let limit = q.limit.filter(|v| *v > 0);

    let ifindex = match resolve_query_iface_to_ifindex(&state, Some(iface.clone())).await {
        Ok(i) => i,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    let runtime = state.monitor_runtime.read().await;
    let histogram = state.histogram.read().await;

    let mut items: Vec<UsageRankingItem> = runtime
        .device_registry
        .entries
        .iter()
        .filter_map(|((dev_ifindex, mac), dev)| {
            if *dev_ifindex != ifindex {
                return None;
            }

            let mac_s = mac_utils::to_string(mac);
            let buckets = histogram.query_aggregate(ifindex, Some(mac_s.as_str()), start_ms, end_ms, AggregateBucket::Daily);
            let mut up: u64 = 0;
            let mut down: u64 = 0;
            for b in buckets.into_iter().map(|b| b.with_traffic_type(tt)) {
                up = up.saturating_add(b.up_v4_bytes.saturating_add(b.up_v6_bytes));
                down = down.saturating_add(b.down_v4_bytes.saturating_add(b.down_v6_bytes));
            }
            let total = up.saturating_add(down);
            if total == 0 {
                return None;
            }

            Some(UsageRankingItem {
                iface: iface.clone(),
                mac: mac_s,
                hostname: dev.hostname.clone(),
                ipv4: dev.ipv4.clone(),
                ipv6: dev.ipv6.clone(),
                up_bytes: up,
                down_bytes: down,
                total_bytes: total,
            })
        })
        .collect();

    items.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes).then(a.mac.cmp(&b.mac)));
    if let Some(limit) = limit {
        items.truncate(limit);
    }

    Ok(Json(ApiEnvelope {
        ok: true,
        data: items,
        error: None,
    }))
}

pub async fn start_server(bind_addr: &str, state: ApiState) -> anyhow::Result<()> {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<ApiEnvelope<&'static str>> {
    Json(ApiEnvelope {
        ok: true,
        data: "ok",
        error: None,
    })
}

async fn snapshot(State(state): State<ApiState>) -> Json<ApiEnvelope<SnapshotData>> {
    Json(ApiEnvelope {
        ok: true,
        data: state.snapshot.read().await.clone(),
        error: None,
    })
}

async fn overview(
    State(state): State<ApiState>,
    Query(q): Query<OverviewQuery>,
) -> Json<ApiEnvelope<Vec<crate::monitor::InterfaceOverviewItem>>> {
    let period = match parse_period_scope(q.period.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            return Json(ApiEnvelope {
                ok: false,
                data: Vec::new(),
                error: Some(e),
            });
        }
    };
    let mut data = state.snapshot.read().await.interfaces.clone();
    if let Some(scope) = period {
        let (start_ms, end_ms) = period_range_ms(scope, now_millis());
        let histogram = state.histogram.read().await;
        for item in &mut data {
            let buckets = histogram.query_aggregate(item.ifindex, None, start_ms, end_ms, AggregateBucket::Hourly);
            item.cumulative = cumulative_from_buckets(&buckets);
        }
    }
    Json(ApiEnvelope {
        ok: true,
        data,
        error: None,
    })
}

async fn devices(State(state): State<ApiState>, Query(q): Query<DevicesQuery>) -> Json<ApiEnvelope<Vec<crate::monitor::DeviceListItem>>> {
    let period = match parse_period_scope(q.period.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            return Json(ApiEnvelope {
                ok: false,
                data: Vec::new(),
                error: Some(e),
            });
        }
    };
    let devices = state.snapshot.read().await.devices.clone();
    let mut filtered: Vec<_> = devices
        .into_iter()
        .filter(|d| {
            if let Some(ref iface) = q.iface {
                if !iface.is_empty() && d.logical_iface != *iface {
                    return false;
                }
            }
            true
        })
        .collect();
    if let Some(scope) = period {
        let (start_ms, end_ms) = period_range_ms(scope, now_millis());
        let histogram = state.histogram.read().await;
        for item in &mut filtered {
            let buckets = histogram.query_aggregate(item.ifindex, Some(item.mac.as_str()), start_ms, end_ms, AggregateBucket::Hourly);
            item.cumulative = cumulative_from_buckets(&buckets);
        }
    }
    Json(ApiEnvelope {
        ok: true,
        data: filtered,
        error: None,
    })
}

async fn set_device_hostname_handler(
    State(state): State<ApiState>,
    Json(req): Json<SetDeviceHostnameRequest>,
) -> Json<ApiEnvelope<&'static str>> {
    let iface = req.iface.trim();
    if iface.is_empty() {
        warn!("api PUT /api/devices/hostname rejected: iface is required");
        return Json(ApiEnvelope {
            ok: false,
            data: "error",
            error: Some("iface is required".to_string()),
        });
    }
    let mac_raw = req.mac.trim();
    if mac_raw.is_empty() {
        warn!("api PUT /api/devices/hostname rejected: mac is required iface={}", iface);
        return Json(ApiEnvelope {
            ok: false,
            data: "error",
            error: Some("mac is required".to_string()),
        });
    }
    let hostname = req.hostname.trim().to_string();
    if hostname.is_empty() {
        warn!(
            "api PUT /api/devices/hostname rejected: hostname is required iface={} mac={}",
            iface, mac_raw
        );
        return Json(ApiEnvelope {
            ok: false,
            data: "error",
            error: Some("hostname is required".to_string()),
        });
    }

    let ifindex = {
        let topo = state.topology.read().await;
        let Some(v) = topo.ifindex_by_name(iface) else {
            warn!(
                "api PUT /api/devices/hostname rejected: unknown iface={} mac={}",
                iface, mac_raw
            );
            return Json(ApiEnvelope {
                ok: false,
                data: "error",
                error: Some(format!("unknown iface: {iface}")),
            });
        };
        v
    };
    let mac = match mac_utils::from_str(mac_raw) {
        Ok(v) => v,
        Err(_) => {
            warn!(
                "api PUT /api/devices/hostname rejected: invalid mac iface={} mac_raw={}",
                iface, mac_raw
            );
            return Json(ApiEnvelope {
                ok: false,
                data: "error",
                error: Some("invalid mac format".to_string()),
            });
        }
    };

    let mac_norm = mac_utils::to_string(&mac);
    let mut snapshot_device: Option<crate::monitor::DeviceListItem> = None;
    {
        let mut snapshot = state.snapshot.write().await;
        for dev in &mut snapshot.devices {
            if dev.ifindex == ifindex && dev.mac.eq_ignore_ascii_case(&mac_norm) {
                dev.hostname = hostname.clone();
                snapshot_device = Some(dev.clone());
            }
        }
    }

    {
        let mut runtime = state.monitor_runtime.write().await;
        if let Some(known) = runtime.device_registry.entries.get_mut(&(ifindex, mac)) {
            known.hostname = hostname.clone();
        } else if let Some(dev) = snapshot_device {
            runtime.device_registry.entries.insert(
                (ifindex, mac),
                KnownDevice {
                    ifindex,
                    mac,
                    ipv4: dev.ipv4,
                    ipv6: dev.ipv6,
                    hostname: hostname.clone(),
                    logical_iface: dev.logical_iface,
                    subnet: dev.subnet,
                    last_seen_ms: now_millis(),
                },
            );
        } else {
            warn!(
                "api PUT /api/devices/hostname rejected: device not found iface={} mac={}",
                iface, mac_norm
            );
            return Json(ApiEnvelope {
                ok: false,
                data: "error",
                error: Some("device not found".to_string()),
            });
        }
    }

    if let Err(e) = persist_monitor_runtime_state(&state).await {
        warn!(
            "api PUT /api/devices/hostname failed persist iface={} mac={} hostname={} err={}",
            iface, mac_norm, hostname, e
        );
        return Json(ApiEnvelope {
            ok: false,
            data: "error",
            error: Some(format!("persist devices state failed: {}", e)),
        });
    }

    info!(
        "api PUT /api/devices/hostname ok iface={} mac={} hostname={}",
        iface, mac_norm, hostname
    );

    Json(ApiEnvelope {
        ok: true,
        data: "ok",
        error: None,
    })
}

#[derive(Debug, Clone, Copy)]
enum PeriodScope {
    Today,
    Week,
    Month,
    Year,
}

fn parse_period_scope(input: Option<&str>) -> Result<Option<PeriodScope>, String> {
    let Some(raw) = input else {
        return Ok(None);
    };
    let s = raw.trim();
    if s.is_empty() {
        return Ok(None);
    }
    match s.to_ascii_lowercase().as_str() {
        "all" => Ok(None),
        "today" => Ok(Some(PeriodScope::Today)),
        "week" => Ok(Some(PeriodScope::Week)),
        "month" => Ok(Some(PeriodScope::Month)),
        "year" => Ok(Some(PeriodScope::Year)),
        _ => Err("invalid period, expected one of: all, today, week, month, year".to_string()),
    }
}

fn period_range_ms(scope: PeriodScope, now_ms: u64) -> (u64, u64) {
    let now = match Local.timestamp_millis_opt(now_ms as i64) {
        chrono::LocalResult::Single(v) => v,
        _ => return (0, now_ms),
    };
    let today_start_naive = now.date_naive().and_hms_milli_opt(0, 0, 0, 0).unwrap();
    let today_start = Local.from_local_datetime(&today_start_naive).unwrap().timestamp_millis() as u64;

    let start = match scope {
        PeriodScope::Today => today_start,
        PeriodScope::Week => {
            let days = now.weekday().num_days_from_monday() as i64;
            let week_start_naive = (now.date_naive() - ChronoDuration::days(days))
                .and_hms_milli_opt(0, 0, 0, 0)
                .unwrap();
            Local.from_local_datetime(&week_start_naive).unwrap().timestamp_millis() as u64
        }
        PeriodScope::Month => {
            let month_start_naive = now.date_naive().with_day(1).unwrap().and_hms_milli_opt(0, 0, 0, 0).unwrap();
            Local.from_local_datetime(&month_start_naive).unwrap().timestamp_millis() as u64
        }
        PeriodScope::Year => {
            let year_start_naive = now
                .date_naive()
                .with_month(1)
                .unwrap()
                .with_day(1)
                .unwrap()
                .and_hms_milli_opt(0, 0, 0, 0)
                .unwrap();
            Local.from_local_datetime(&year_start_naive).unwrap().timestamp_millis() as u64
        }
    };
    (start, now_ms)
}

fn cumulative_from_buckets(buckets: &[AggregatedBucket]) -> crate::monitor::CounterQuad {
    let mut out = crate::monitor::CounterQuad::default();
    for b in buckets {
        out.up_v4_bytes = out.up_v4_bytes.saturating_add(b.up_v4_bytes);
        out.down_v4_bytes = out.down_v4_bytes.saturating_add(b.down_v4_bytes);
        out.up_v6_bytes = out.up_v6_bytes.saturating_add(b.up_v6_bytes);
        out.down_v6_bytes = out.down_v6_bytes.saturating_add(b.down_v6_bytes);
    }
    out
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

async fn resolve_query_iface_to_ifindex(state: &ApiState, iface: Option<String>) -> Result<u32, String> {
    let name = iface
        .and_then(|s| {
            let t = s.trim();
            if t.is_empty() { None } else { Some(t.to_string()) }
        })
        .ok_or_else(|| "iface is required".to_string())?;

    let topo = state.topology.read().await;
    if let Some(ix) = topo.ifindex_by_name(&name) {
        return Ok(ix);
    }
    drop(topo);

    let snap = state.snapshot.read().await;
    for item in &snap.interfaces {
        if item.ifname == name {
            return Ok(item.ifindex);
        }
    }

    Err(format!("unknown iface: {name}"))
}

async fn history(State(state): State<ApiState>, Query(q): Query<HistoryQuery>) -> Json<ApiEnvelope<Vec<HistorySample>>> {
    let ifindex = match resolve_query_iface_to_ifindex(&state, q.iface.clone()).await {
        Ok(i) => i,
        Err(e) => {
            return Json(ApiEnvelope {
                ok: false,
                data: Vec::new(),
                error: Some(e),
            });
        }
    };
    let traffic_type = parse_traffic_type(q.traffic_type.as_deref());
    let direction = parse_direction(q.direction.as_deref());
    let result = if let Some(mac) = q.mac.as_deref().filter(|s| !s.trim().is_empty()) {
        state
            .history
            .read()
            .await
            .query_device(Some(ifindex), mac, traffic_type, direction)
    } else {
        state.history.read().await.query_iface(ifindex, traffic_type, direction)
    };
    Json(ApiEnvelope {
        ok: true,
        data: result,
        error: None,
    })
}

fn parse_traffic_type(input: Option<&str>) -> HistoryTrafficType {
    match input.unwrap_or("all").to_ascii_lowercase().as_str() {
        "ipv4" => HistoryTrafficType::Ipv4,
        "ipv6" => HistoryTrafficType::Ipv6,
        _ => HistoryTrafficType::All,
    }
}

fn parse_direction(input: Option<&str>) -> HistoryDirection {
    match input.unwrap_or("both").to_ascii_lowercase().as_str() {
        "up" => HistoryDirection::Up,
        "down" => HistoryDirection::Down,
        _ => HistoryDirection::Both,
    }
}

async fn aggregate(State(state): State<ApiState>, Query(q): Query<AggregateQuery>) -> Json<ApiEnvelope<Vec<AggregatedBucket>>> {
    let ifindex = match resolve_query_iface_to_ifindex(&state, q.iface.clone()).await {
        Ok(i) => i,
        Err(e) => {
            return Json(ApiEnvelope {
                ok: false,
                data: Vec::new(),
                error: Some(e),
            });
        }
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let default_end = now_ms;
    let default_start = now_ms.saturating_sub(24 * 3600 * 1000);
    let start_ms = q.start_ms.unwrap_or(default_start);
    let end_ms = q.end_ms.unwrap_or(default_end);
    let bucket = match q.bucket.as_deref().unwrap_or("hourly").to_ascii_lowercase().as_str() {
        "daily" => AggregateBucket::Daily,
        _ => AggregateBucket::Hourly,
    };
    let traffic_type = parse_traffic_type(q.traffic_type.as_deref());
    let mac_filter = q.mac.as_deref().filter(|s| !s.trim().is_empty());

    let result: Vec<AggregatedBucket> = if let Some(mac) = mac_filter {
        let histogram = state.histogram.read().await;
        histogram
            .query_aggregate(ifindex, Some(mac), start_ms, end_ms, bucket)
            .into_iter()
            .map(|b| b.with_traffic_type(traffic_type))
            .collect()
    } else {
        // "all devices" 口径：按设备维度聚合后再求和，避免包含无法归属到设备的流量。
        let runtime = state.monitor_runtime.read().await;
        let mut macs = Vec::new();
        for ((dev_ifindex, mac), _dev) in &runtime.device_registry.entries {
            if *dev_ifindex == ifindex {
                macs.push(mac_utils::to_string(mac));
            }
        }
        drop(runtime);

        let histogram = state.histogram.read().await;
        let mut by_window: BTreeMap<(u64, u64), AggregatedBucket> = BTreeMap::new();
        for mac in macs {
            let buckets = histogram.query_aggregate(ifindex, Some(mac.as_str()), start_ms, end_ms, bucket);
            for b in buckets {
                let key = (b.start_ts_ms, b.end_ts_ms);
                let entry = by_window.entry(key).or_insert_with(|| empty_bucket(key.0, key.1));
                accumulate_bucket(entry, &b);
            }
        }

        by_window.into_values().map(|b| b.with_traffic_type(traffic_type)).collect()
    };
    Json(ApiEnvelope {
        ok: true,
        data: result,
        error: None,
    })
}

fn empty_bucket(start_ts_ms: u64, end_ts_ms: u64) -> AggregatedBucket {
    AggregatedBucket {
        start_ts_ms,
        end_ts_ms,
        up_v4_bytes: 0,
        down_v4_bytes: 0,
        up_v6_bytes: 0,
        down_v6_bytes: 0,
        up_v4_bps_avg: 0,
        up_v4_bps_max: 0,
        up_v4_bps_min: 0,
        up_v4_bps_p95: 0,
        down_v4_bps_avg: 0,
        down_v4_bps_max: 0,
        down_v4_bps_min: 0,
        down_v4_bps_p95: 0,
        up_v6_bps_avg: 0,
        up_v6_bps_max: 0,
        up_v6_bps_min: 0,
        up_v6_bps_p95: 0,
        down_v6_bps_avg: 0,
        down_v6_bps_max: 0,
        down_v6_bps_min: 0,
        down_v6_bps_p95: 0,
    }
}

fn accumulate_bucket(dst: &mut AggregatedBucket, src: &AggregatedBucket) {
    dst.up_v4_bytes = dst.up_v4_bytes.saturating_add(src.up_v4_bytes);
    dst.down_v4_bytes = dst.down_v4_bytes.saturating_add(src.down_v4_bytes);
    dst.up_v6_bytes = dst.up_v6_bytes.saturating_add(src.up_v6_bytes);
    dst.down_v6_bytes = dst.down_v6_bytes.saturating_add(src.down_v6_bytes);
    dst.up_v4_bps_avg = dst.up_v4_bps_avg.saturating_add(src.up_v4_bps_avg);
    dst.up_v4_bps_max = dst.up_v4_bps_max.saturating_add(src.up_v4_bps_max);
    dst.up_v4_bps_min = dst.up_v4_bps_min.saturating_add(src.up_v4_bps_min);
    dst.up_v4_bps_p95 = dst.up_v4_bps_p95.saturating_add(src.up_v4_bps_p95);
    dst.down_v4_bps_avg = dst.down_v4_bps_avg.saturating_add(src.down_v4_bps_avg);
    dst.down_v4_bps_max = dst.down_v4_bps_max.saturating_add(src.down_v4_bps_max);
    dst.down_v4_bps_min = dst.down_v4_bps_min.saturating_add(src.down_v4_bps_min);
    dst.down_v4_bps_p95 = dst.down_v4_bps_p95.saturating_add(src.down_v4_bps_p95);
    dst.up_v6_bps_avg = dst.up_v6_bps_avg.saturating_add(src.up_v6_bps_avg);
    dst.up_v6_bps_max = dst.up_v6_bps_max.saturating_add(src.up_v6_bps_max);
    dst.up_v6_bps_min = dst.up_v6_bps_min.saturating_add(src.up_v6_bps_min);
    dst.up_v6_bps_p95 = dst.up_v6_bps_p95.saturating_add(src.up_v6_bps_p95);
    dst.down_v6_bps_avg = dst.down_v6_bps_avg.saturating_add(src.down_v6_bps_avg);
    dst.down_v6_bps_max = dst.down_v6_bps_max.saturating_add(src.down_v6_bps_max);
    dst.down_v6_bps_min = dst.down_v6_bps_min.saturating_add(src.down_v6_bps_min);
    dst.down_v6_bps_p95 = dst.down_v6_bps_p95.saturating_add(src.down_v6_bps_p95);
}

async fn policy(State(state): State<ApiState>) -> Json<ApiEnvelope<Vec<PolicyItem>>> {
    let data = {
        let guard = state.policy_runtime.read().await;
        policy_items(&guard)
    };
    Json(ApiEnvelope {
        ok: true,
        data,
        error: None,
    })
}

async fn get_schedules(State(state): State<ApiState>) -> Json<ApiEnvelope<Vec<ScheduledRuleApi>>> {
    let data = {
        let guard = state.policy_runtime.read().await;
        get_scheduled_rules(&guard)
    };
    Json(ApiEnvelope {
        ok: true,
        data,
        error: None,
    })
}

async fn create_schedule(State(state): State<ApiState>, Json(req): Json<CreateScheduledRuleRequest>) -> impl IntoResponse {
    let ts = &req.time_slot;
    info!(
        "api POST /api/rate_limit/schedules call iface={} mac={} time={}-{} days={:?} kbps d4={} d6={} u4={} u6={}",
        req.iface, req.mac, ts.start, ts.end, ts.days, req.down_v4_kbps, req.down_v6_kbps, req.up_v4_kbps, req.up_v6_kbps
    );
    let result = {
        let topo = state.topology.read().await;
        let mut guard = state.policy_runtime.write().await;
        create_scheduled_rule(&mut guard, req, &topo)
    };
    match result {
        Ok(v) => {
            if let Err(e) = persist_policy_state(&state).await {
                warn!(
                    "api POST /api/rate_limit/schedules failed persist after rule id={} err={}",
                    v.id, e
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiEnvelope::<ScheduledRuleApi> {
                        ok: false,
                        data: ScheduledRuleApi {
                            id: String::new(),
                            iface: String::new(),
                            mac: String::new(),
                            time_slot: crate::policy::TimeSlotApi {
                                start: String::new(),
                                end: String::new(),
                                days: vec![],
                            },
                            down_v4_kbps: 0,
                            down_v6_kbps: 0,
                            up_v4_kbps: 0,
                            up_v6_kbps: 0,
                        },
                        error: Some(format!("persist policy failed: {}", e)),
                    }),
                )
                    .into_response();
            }
            info!(
                "api POST /api/rate_limit/schedules ok id={} iface={} mac={}",
                v.id, v.iface, v.mac
            );
            Json(ApiEnvelope {
                ok: true,
                data: v,
                error: None,
            })
            .into_response()
        }
        Err(e) => {
            warn!("api POST /api/rate_limit/schedules rejected err={}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ApiEnvelope::<ScheduledRuleApi> {
                    ok: false,
                    data: ScheduledRuleApi {
                        id: String::new(),
                        iface: String::new(),
                        mac: String::new(),
                        time_slot: crate::policy::TimeSlotApi {
                            start: String::new(),
                            end: String::new(),
                            days: vec![],
                        },
                        down_v4_kbps: 0,
                        down_v6_kbps: 0,
                        up_v4_kbps: 0,
                        up_v6_kbps: 0,
                    },
                    error: Some(e.to_string()),
                }),
            )
                .into_response()
        }
    }
}

async fn update_schedule(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateScheduledRuleRequest>,
) -> impl IntoResponse {
    let ts = &req.time_slot;
    info!(
        "api PUT /api/rate_limit/schedules/{{id}} call id={} iface={} mac={} time={}-{} days={:?} kbps d4={} d6={} u4={} u6={}",
        id, req.iface, req.mac, ts.start, ts.end, ts.days, req.down_v4_kbps, req.down_v6_kbps, req.up_v4_kbps, req.up_v6_kbps
    );
    let result = {
        let topo = state.topology.read().await;
        let mut guard = state.policy_runtime.write().await;
        update_scheduled_rule(&mut guard, &id, req, &topo)
    };
    match result {
        Ok(v) => {
            if let Err(e) = persist_policy_state(&state).await {
                warn!(
                    "api PUT/PATCH /api/rate_limit/schedules/{{id}} failed persist id={} err={}",
                    id, e
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiEnvelope::<ScheduledRuleApi> {
                        ok: false,
                        data: ScheduledRuleApi {
                            id: String::new(),
                            iface: String::new(),
                            mac: String::new(),
                            time_slot: crate::policy::TimeSlotApi {
                                start: String::new(),
                                end: String::new(),
                                days: vec![],
                            },
                            down_v4_kbps: 0,
                            down_v6_kbps: 0,
                            up_v4_kbps: 0,
                            up_v6_kbps: 0,
                        },
                        error: Some(format!("persist policy failed: {}", e)),
                    }),
                )
                    .into_response();
            }
            info!(
                "api PUT/PATCH /api/rate_limit/schedules/{{id}} ok id={} iface={} mac={}",
                v.id, v.iface, v.mac
            );
            Json(ApiEnvelope {
                ok: true,
                data: v,
                error: None,
            })
            .into_response()
        }
        Err(e) => {
            warn!("api PUT/PATCH /api/rate_limit/schedules/{{id}} rejected id={} err={}", id, e);
            (
                StatusCode::BAD_REQUEST,
                Json(ApiEnvelope::<ScheduledRuleApi> {
                    ok: false,
                    data: ScheduledRuleApi {
                        id: String::new(),
                        iface: String::new(),
                        mac: String::new(),
                        time_slot: crate::policy::TimeSlotApi {
                            start: String::new(),
                            end: String::new(),
                            days: vec![],
                        },
                        down_v4_kbps: 0,
                        down_v6_kbps: 0,
                        up_v4_kbps: 0,
                        up_v6_kbps: 0,
                    },
                    error: Some(e.to_string()),
                }),
            )
                .into_response()
        }
    }
}

async fn delete_schedule(State(state): State<ApiState>, Path(id): Path<String>) -> Json<ApiEnvelope<&'static str>> {
    info!("api DELETE /api/rate_limit/schedules/{{id}} call id={}", id);
    let result = {
        let mut guard = state.policy_runtime.write().await;
        delete_scheduled_rule(&mut guard, &id)
    };
    if let Err(e) = result {
        warn!("api DELETE /api/rate_limit/schedules/{{id}} rejected id={} err={}", id, e);
        return Json(ApiEnvelope {
            ok: false,
            data: "error",
            error: Some(e.to_string()),
        });
    }
    if let Err(e) = persist_policy_state(&state).await {
        warn!("api DELETE /api/rate_limit/schedules/{{id}} failed persist id={} err={}", id, e);
        return Json(ApiEnvelope {
            ok: false,
            data: "error",
            error: Some(format!("persist policy failed: {}", e)),
        });
    }
    info!("api DELETE /api/rate_limit/schedules/{{id}} ok id={}", id);
    Json(ApiEnvelope {
        ok: true,
        data: "ok",
        error: None,
    })
}

async fn get_iface_limits_handler(State(state): State<ApiState>) -> Json<ApiEnvelope<Vec<InterfaceRateLimitApi>>> {
    let data = {
        let guard = state.policy_runtime.read().await;
        get_iface_limits(&guard)
    };
    Json(ApiEnvelope {
        ok: true,
        data,
        error: None,
    })
}

async fn set_iface_limit_handler(
    State(state): State<ApiState>,
    Json(req): Json<SetInterfaceRateLimitRequest>,
) -> Json<ApiEnvelope<&'static str>> {
    let result = {
        let topology_guard = state.topology.read().await;
        let mut guard = state.policy_runtime.write().await;
        set_iface_limit(&mut guard, req, &topology_guard)
    };
    to_simple_response_with_persist(&state, result).await
}

async fn delete_iface_limit_handler(State(state): State<ApiState>, Path(iface): Path<String>) -> Json<ApiEnvelope<&'static str>> {
    let result = {
        let mut guard = state.policy_runtime.write().await;
        delete_iface_limit(&mut guard, &iface)
    };
    to_simple_response_with_persist(&state, result).await
}

async fn get_guest_defaults_handler(State(state): State<ApiState>) -> Json<ApiEnvelope<Vec<GuestDefaultRateLimitApi>>> {
    let data = {
        let guard = state.policy_runtime.read().await;
        get_guest_defaults(&guard)
    };
    Json(ApiEnvelope {
        ok: true,
        data,
        error: None,
    })
}

async fn set_guest_default_handler(
    State(state): State<ApiState>,
    Json(req): Json<SetInterfaceRateLimitRequest>,
) -> Json<ApiEnvelope<&'static str>> {
    info!(
        "api POST /api/rate_limit/guest_defaults call iface={} kbps d4={} d6={} u4={} u6={}",
        req.iface, req.down_v4_kbps, req.down_v6_kbps, req.up_v4_kbps, req.up_v6_kbps
    );
    let result = {
        let topology_guard = state.topology.read().await;
        let mut guard = state.policy_runtime.write().await;
        set_guest_default(&mut guard, req, &topology_guard)
    };
    to_simple_response_with_persist(&state, result).await
}

async fn delete_guest_default_handler(State(state): State<ApiState>, Path(iface): Path<String>) -> Json<ApiEnvelope<&'static str>> {
    info!("api DELETE /api/rate_limit/guest_defaults/{iface} call iface={}", iface);
    let result = {
        let mut guard = state.policy_runtime.write().await;
        delete_guest_default(&mut guard, &iface)
    };
    to_simple_response_with_persist(&state, result).await
}

async fn set_guest_default_enable_handler(
    State(state): State<ApiState>,
    Path(iface): Path<String>,
    Json(req): Json<SetEnabledRequest>,
) -> Json<ApiEnvelope<&'static str>> {
    info!(
        "api PUT /api/rate_limit/guest_defaults/{iface}/enable call iface={} enabled={}",
        iface, req.enabled
    );
    let result = {
        let mut guard = state.policy_runtime.write().await;
        set_guest_default_enabled(&mut guard, &iface, req.enabled)
    };
    to_simple_response_with_persist(&state, result).await
}

async fn get_guest_whitelist_handler(State(state): State<ApiState>) -> Json<ApiEnvelope<Vec<GuestWhitelistEntryApi>>> {
    let data = {
        let guard = state.policy_runtime.read().await;
        get_guest_whitelist(&guard)
    };
    Json(ApiEnvelope {
        ok: true,
        data,
        error: None,
    })
}

async fn add_guest_whitelist_handler(
    State(state): State<ApiState>,
    Json(req): Json<GuestWhitelistEntryRequest>,
) -> Json<ApiEnvelope<&'static str>> {
    info!(
        "api POST /api/rate_limit/guest_whitelist call iface={} mac={}",
        req.iface, req.mac
    );
    let result = {
        let topology_guard = state.topology.read().await;
        let mut guard = state.policy_runtime.write().await;
        add_guest_whitelist(&mut guard, req, &topology_guard)
    };
    to_simple_response_with_persist(&state, result).await
}

async fn remove_guest_whitelist_handler(
    State(state): State<ApiState>,
    Json(req): Json<GuestWhitelistEntryRequest>,
) -> Json<ApiEnvelope<&'static str>> {
    info!(
        "api DELETE /api/rate_limit/guest_whitelist call iface={} mac={}",
        req.iface, req.mac
    );
    let result = {
        let mut guard = state.policy_runtime.write().await;
        remove_guest_whitelist(&mut guard, req)
    };
    to_simple_response_with_persist(&state, result).await
}

async fn to_simple_response_with_persist(state: &ApiState, result: anyhow::Result<()>) -> Json<ApiEnvelope<&'static str>> {
    if let Err(e) = result {
        return Json(ApiEnvelope {
            ok: false,
            data: "error",
            error: Some(e.to_string()),
        });
    }
    if let Err(e) = persist_policy_state(state).await {
        return Json(ApiEnvelope {
            ok: false,
            data: "error",
            error: Some(format!("persist policy failed: {}", e)),
        });
    }
    Json(ApiEnvelope {
        ok: true,
        data: "ok",
        error: None,
    })
}

async fn persist_policy_state(state: &ApiState) -> anyhow::Result<()> {
    if let Some(p) = &state.persistence {
        let guard = state.policy_runtime.read().await;
        p.save_policy_runtime(&guard)?;
    }
    Ok(())
}

async fn persist_monitor_runtime_state(state: &ApiState) -> anyhow::Result<()> {
    if let Some(p) = &state.persistence {
        let runtime = state.monitor_runtime.read().await;
        let topo = state.topology.read().await;
        p.save_monitor_runtime(&runtime, &topo)?;
    }
    Ok(())
}

async fn persist_traffic(State(state): State<ApiState>) -> Json<ApiEnvelope<&'static str>> {
    if !state.traffic_enable_storage || state.persistence.is_none() {
        return Json(ApiEnvelope {
            ok: false,
            data: "error",
            error: Some("traffic storage is not enabled".to_string()),
        });
    }

    match persist_traffic_state(&state).await {
        Ok(_) => Json(ApiEnvelope {
            ok: true,
            data: "ok",
            error: None,
        }),
        Err(e) => Json(ApiEnvelope {
            ok: false,
            data: "error",
            error: Some(format!("persist traffic failed: {}", e)),
        }),
    }
}

async fn persist_traffic_state(state: &ApiState) -> anyhow::Result<()> {
    if let Some(p) = &state.persistence {
        let topo = state.topology.read().await;
        let runtime = state.monitor_runtime.read().await;
        p.save_monitor_runtime(&runtime, &topo)?;

        let histogram = state.histogram.read().await;
        p.save_current_hour_histogram(&histogram, &topo)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::{CounterQuad, DeviceListItem, MonitorRuntime};
    use crate::policy::{init_runtime, parse_policy};
    use crate::topology::{Interface, InterfaceZone, TopologySnapshot};
    use crate::utils::system_utils::InterfaceRole;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn mock_api_state() -> ApiState {
        let topo = TopologySnapshot::from_interfaces(vec![
            Interface {
                ifindex: 1,
                name: "eth0".to_string(),
                role: InterfaceRole::Ethernet,
                zone: InterfaceZone::Other,
                parent_ifindex: None,
                ipv4_cidrs: vec![],
                ipv6_cidrs: vec![],
            },
            Interface {
                ifindex: 2,
                name: "guest0".to_string(),
                role: InterfaceRole::Ethernet,
                zone: InterfaceZone::Guest,
                parent_ifindex: None,
                ipv4_cidrs: vec![],
                ipv6_cidrs: vec![],
            },
        ]);
        ApiState {
            snapshot: Arc::new(RwLock::new(SnapshotData::default())),
            history: Arc::new(RwLock::new(TrafficHistory::new(60))),
            histogram: Arc::new(RwLock::new(HistogramHistory::new())),
            monitor_runtime: Arc::new(RwLock::new(MonitorRuntime::default())),
            policy_runtime: Arc::new(RwLock::new(init_runtime(parse_policy()))),
            topology: Arc::new(RwLock::new(topo)),
            persistence: None,
            traffic_enable_storage: false,
        }
    }

    #[tokio::test]
    async fn api_health() {
        let app = router(mock_api_state());
        let req = Request::get("/api/health").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let env: ApiEnvelope<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(env.ok);
    }

    #[tokio::test]
    async fn api_snapshot() {
        let app = router(mock_api_state());
        let req = Request::get("/api/snapshot").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_overview() {
        let app = router(mock_api_state());
        let req = Request::get("/api/overview").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_overview_with_period_today() {
        let app = router(mock_api_state());
        let req = Request::get("/api/overview?period=today").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let env: ApiEnvelope<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(env.ok);
    }

    #[tokio::test]
    async fn api_devices() {
        let app = router(mock_api_state());
        let req = Request::get("/api/devices").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_devices_with_iface_filter() {
        let app = router(mock_api_state());
        let req = Request::get("/api/devices?iface=eth0").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_devices_with_period_all() {
        let app = router(mock_api_state());
        let req = Request::get("/api/devices?period=all").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let env: ApiEnvelope<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(env.ok);
    }

    #[tokio::test]
    async fn api_devices_with_invalid_period() {
        let app = router(mock_api_state());
        let req = Request::get("/api/devices?period=invalid").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let env: ApiEnvelope<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(!env.ok);
        assert!(env.error.unwrap().contains("period"));
    }

    #[tokio::test]
    async fn api_set_device_hostname() {
        let state = mock_api_state();
        {
            let mut snap = state.snapshot.write().await;
            snap.devices.push(DeviceListItem {
                ifindex: 1,
                logical_iface: "eth0".to_string(),
                subnet: "-".to_string(),
                ipv4: vec!["192.168.1.2".to_string()],
                ipv6: vec![],
                mac: "aa:bb:cc:dd:ee:ff".to_string(),
                hostname: "old-name".to_string(),
                metrics: CounterQuad::default(),
                cumulative: CounterQuad::default(),
                online: true,
                last_seen_ms: 0,
                neighbor_state: Some("REACHABLE".to_string()),
            });
        }

        let app = router(state.clone());
        let body = serde_json::json!({
            "iface": "eth0",
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "my-phone"
        });
        let req = Request::put("/api/devices/hostname")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let env: ApiEnvelope<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(env.ok);

        let snap = state.snapshot.read().await;
        let item = snap
            .devices
            .iter()
            .find(|d| d.ifindex == 1 && d.mac.eq_ignore_ascii_case("aa:bb:cc:dd:ee:ff"))
            .unwrap();
        assert_eq!(item.hostname, "my-phone");
        drop(snap);

        let mac = crate::utils::mac_utils::from_str("aa:bb:cc:dd:ee:ff").unwrap();
        let runtime = state.monitor_runtime.read().await;
        let known = runtime.device_registry.entries.get(&(1, mac)).unwrap();
        assert_eq!(known.hostname, "my-phone");
    }

    #[tokio::test]
    async fn api_set_device_hostname_invalid_iface() {
        let app = router(mock_api_state());
        let body = serde_json::json!({
            "iface": "not-exist",
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "my-phone"
        });
        let req = Request::put("/api/devices/hostname")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let env: ApiEnvelope<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(!env.ok);
        assert!(env.error.unwrap().contains("unknown iface"));
    }

    #[tokio::test]
    async fn api_policy() {
        let app = router(mock_api_state());
        let req = Request::get("/api/policy").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_trend_missing_iface() {
        let app = router(mock_api_state());
        let req = Request::get("/api/trend").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let env: ApiEnvelope<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(!env.ok);
        assert!(env.error.unwrap().contains("iface"));
    }

    #[tokio::test]
    async fn api_trend_by_iface() {
        let app = router(mock_api_state());
        let req = Request::get("/api/trend?iface=eth0").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let env: ApiEnvelope<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(env.ok);
    }

    #[tokio::test]
    async fn api_histogram_missing_iface() {
        let app = router(mock_api_state());
        let req = Request::get("/api/histogram").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let env: ApiEnvelope<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(!env.ok);
        assert!(env.error.unwrap().contains("iface"));
    }

    #[tokio::test]
    async fn api_histogram_by_iface_with_traffic_type() {
        let app = router(mock_api_state());
        let req = Request::get("/api/histogram?iface=eth0&traffic_type=ipv4")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let env: ApiEnvelope<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(env.ok);
    }

    #[tokio::test]
    async fn api_schedules_get() {
        let app = router(mock_api_state());
        let req = Request::get("/api/rate_limit/schedules").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_schedules_post_valid() {
        let app = router(mock_api_state());
        let body = serde_json::json!({
            "iface": "eth0",
            "mac": "aa:bb:cc:dd:ee:ff",
            "time_slot": { "start": "09:00", "end": "18:00", "days": [1,2,3,4,5] },
            "down_v4_kbps": 100,
            "down_v6_kbps": 100,
            "up_v4_kbps": 100,
            "up_v6_kbps": 100
        });
        let req = Request::post("/api/rate_limit/schedules")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_schedules_post_invalid_time() {
        let app = router(mock_api_state());
        let body = serde_json::json!({
            "iface": "eth0",
            "mac": "aa:bb:cc:dd:ee:ff",
            "time_slot": { "start": "99:00", "end": "18:00", "days": [1,2,3,4,5] },
            "down_v4_kbps": 100,
            "down_v6_kbps": 100,
            "up_v4_kbps": 100,
            "up_v6_kbps": 100
        });
        let req = Request::post("/api/rate_limit/schedules")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn api_schedules_delete_not_exists() {
        let app = router(mock_api_state());
        let req = Request::delete("/api/rate_limit/schedules/nonexistent-id")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let env: ApiEnvelope<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(!env.ok);
    }

    #[tokio::test]
    async fn api_iface_limits_get() {
        let app = router(mock_api_state());
        let req = Request::get("/api/rate_limit/iface_limits").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_iface_limits_post() {
        let app = router(mock_api_state());
        let body = serde_json::json!({
            "iface": "eth0",
            "down_v4_kbps": 200,
            "down_v6_kbps": 100,
            "up_v4_kbps": 160,
            "up_v6_kbps": 80
        });
        let req = Request::post("/api/rate_limit/iface_limits")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_guest_defaults_get() {
        let app = router(mock_api_state());
        let req = Request::get("/api/rate_limit/guest_defaults").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_guest_defaults_post() {
        let app = router(mock_api_state());
        let body = serde_json::json!({
            "iface": "guest0",
            "down_v4_kbps": 50,
            "down_v6_kbps": 50,
            "up_v4_kbps": 50,
            "up_v6_kbps": 50
        });
        let req = Request::post("/api/rate_limit/guest_defaults")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_guest_defaults_enable_toggle() {
        let app = router(mock_api_state());
        let set_body = serde_json::json!({
            "iface": "guest0",
            "down_v4_kbps": 50,
            "down_v6_kbps": 50,
            "up_v4_kbps": 50,
            "up_v6_kbps": 50
        });
        let set_req = Request::post("/api/rate_limit/guest_defaults")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&set_body).unwrap()))
            .unwrap();
        let set_res = app.clone().oneshot(set_req).await.unwrap();
        assert_eq!(set_res.status(), StatusCode::OK);

        let disable_body = serde_json::json!({ "enabled": false });
        let disable_req = Request::put("/api/rate_limit/guest_defaults/guest0/enable")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&disable_body).unwrap()))
            .unwrap();
        let disable_res = app.clone().oneshot(disable_req).await.unwrap();
        assert_eq!(disable_res.status(), StatusCode::OK);

        let get_req = Request::get("/api/rate_limit/guest_defaults").body(Body::empty()).unwrap();
        let get_res = app.oneshot(get_req).await.unwrap();
        assert_eq!(get_res.status(), StatusCode::OK);
        let bytes = get_res.into_body().collect().await.unwrap().to_bytes();
        let env: ApiEnvelope<Vec<serde_json::Value>> = serde_json::from_slice(&bytes).unwrap();
        assert!(env.ok);
        assert_eq!(env.data.len(), 1);
        assert_eq!(env.data[0]["iface"], serde_json::Value::String("guest0".to_string()));
        assert_eq!(env.data[0]["enabled"], serde_json::Value::Bool(false));
    }

    #[tokio::test]
    async fn api_guest_whitelist_get() {
        let app = router(mock_api_state());
        let req = Request::get("/api/rate_limit/guest_whitelist").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_guest_whitelist_post() {
        let app = router(mock_api_state());
        let body = serde_json::json!({
            "iface": "guest0",
            "mac": "aa:bb:cc:dd:ee:ff"
        });
        let req = Request::post("/api/rate_limit/guest_whitelist")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_guest_whitelist_delete() {
        let app = router(mock_api_state());
        let body = serde_json::json!({
            "iface": "guest0",
            "mac": "aa:bb:cc:dd:ee:ff"
        });
        let req = Request::builder()
            .method("DELETE")
            .uri("/api/rate_limit/guest_whitelist")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
