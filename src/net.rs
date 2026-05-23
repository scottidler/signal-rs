//! Connection-assembly helpers for `libsignal-net`.
//!
//! `libsignal-net` does not export a single "connect" function for non-bridge
//! Rust consumers. The bridge layer (`libsignal-bridge-types`) wraps it for
//! Java/Swift/JS; for a pure-Rust client we assemble the primitives ourselves.
//!
//! The shape mirrors `libsignal_net::chat::test_support::simple_chat_connection`
//! (which lives behind the `test-util` feature in libsignal-net) but is
//! production-quality and selects the provisioning vs authenticated endpoint
//! per call site.

use std::time::Duration;

use http::HeaderName;
use libsignal_net::chat::{
    AuthenticatedChatHeaders, ChatConnection, ChatHeaders, ConnectError, RECOMMENDED_CHAT_WS_CONFIG,
    UnauthenticatedChatHeaders, ws,
};
use libsignal_net::connect_state::{
    ConnectState, ConnectionResources, DefaultConnectorFactory, PreconnectingFactory, SUGGESTED_CONNECT_CONFIG,
};
use libsignal_net::env::constants::{CHAT_PROVISIONING_PATH, CHAT_WEBSOCKET_PATH};
use libsignal_net::env::{Env, StaticIpOrder, UserAgent};
use libsignal_net::infra::EnableDomainFronting;
use libsignal_net::infra::OverrideNagleAlgorithm;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::route::{DirectOrProxyMode, DirectOrProxyProvider};
use libsignal_net::infra::utils::no_network_change_events;
use log::{debug, info};
use thiserror::Error;
use tokio::sync::mpsc;

const INITIAL_REQUEST_ID: u64 = 0;

#[derive(Error, Debug)]
pub enum NetError {
    #[error("libsignal-net connect error: {0}")]
    Connect(#[from] ConnectError),
}

/// Where to point this connection at. Production targets the live Signal
/// servers; staging is for development against signal-staging.
#[derive(Debug, Clone, Copy)]
pub enum Environment {
    Production,
    Staging,
}

impl Environment {
    fn as_env(self) -> Env<'static> {
        match self {
            Environment::Production => libsignal_net::env::PROD,
            Environment::Staging => libsignal_net::env::STAGING,
        }
    }
}

/// Assemble a ChatConnection for one of the two endpoint paths
/// (`CHAT_WEBSOCKET_PATH` for authenticated/unauthenticated chat,
/// `CHAT_PROVISIONING_PATH` for the link-device flow). Returns the chat
/// connection plus an mpsc receiver that surfaces every `ws::ListenerEvent`
/// from the underlying socket - downstream code converts those to the typed
/// `ProvisioningEvent` / `ServerEvent` per endpoint kind.
async fn connect_endpoint(
    env_kind: Environment,
    endpoint_path: &'static str,
    headers: Option<ChatHeaders>,
    log_tag: &str,
) -> Result<(ChatConnection, mpsc::UnboundedReceiver<ws::ListenerEvent>), NetError> {
    debug!(
        "connect_endpoint: env={:?} endpoint_path={} authenticated={} log_tag={}",
        env_kind,
        endpoint_path,
        headers.is_some(),
        log_tag,
    );

    let env = env_kind.as_env();
    let dns_resolver = DnsResolver::new_with_static_fallback(
        env.static_fallback(StaticIpOrder::HARDCODED),
        &no_network_change_events(),
    );

    let route_provider = DirectOrProxyProvider {
        inner: env
            .chat_domain_config
            .connect
            .route_provider(EnableDomainFronting::No, OverrideNagleAlgorithm::UseSystemDefault),
        mode: DirectOrProxyMode::DirectOnly,
    };

    let connect = ConnectState::new_with_transport_connector(
        SUGGESTED_CONNECT_CONFIG,
        PreconnectingFactory::new(DefaultConnectorFactory, Duration::ZERO),
    );

    let user_agent = UserAgent::with_libsignal_version(concat!("signal-rs/", env!("CARGO_PKG_VERSION")));

    // Adopt libsignal's RECOMMENDED_CHAT_WS_CONFIG (local_idle=31s,
    // remote_idle=45s, post_request_check=5s). Our earlier
    // local==remote=60s config caused the disconnect threshold to fire
    // at the same instant as the keepalive ping, killing the
    // provisioning WebSocket the moment the user took longer than 60s
    // to scan the QR.
    let ws_config = ws::Config {
        initial_request_id: INITIAL_REQUEST_ID,
        ..RECOMMENDED_CHAT_WS_CONFIG
    };

    let confirmation_header_name = env
        .chat_domain_config
        .connect
        .confirmation_header_name
        .map(HeaderName::from_static);

    let connection_resources = ConnectionResources {
        connect_state: &connect,
        dns_resolver: &dns_resolver,
        network_change_event: &no_network_change_events(),
        confirmation_header_name,
    };

    let pending = ChatConnection::start_connect_with(
        connection_resources,
        env.chat_domain_config.connect.service,
        route_provider,
        endpoint_path,
        &user_agent,
        ws_config,
        headers,
        log_tag,
    )
    .await?;

    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let listener: ws::EventListener = Box::new(move |event: ws::ListenerEvent| {
        let _ = event_tx.send(event);
    });

    let tokio_runtime = tokio::runtime::Handle::current();
    let chat = ChatConnection::finish_connect(tokio_runtime, pending, Default::default(), listener);

    info!("connect_endpoint: established (endpoint_path={endpoint_path}, log_tag={log_tag})");
    Ok((chat, event_rx))
}

/// Open an unauthenticated provisioning WebSocket. The returned receiver
/// surfaces raw `ws::ListenerEvent`s - the caller maps them to the typed
/// `libsignal_net::chat::server_requests::ProvisioningEvent` via
/// `ProvisioningEvent::try_from(event)`.
pub async fn connect_provisioning(
    env_kind: Environment,
) -> Result<(ChatConnection, mpsc::UnboundedReceiver<ws::ListenerEvent>), NetError> {
    debug!("connect_provisioning: env={:?}", env_kind);
    let headers = ChatHeaders::Unauth(UnauthenticatedChatHeaders {
        languages: Default::default(),
    });
    connect_endpoint(env_kind, CHAT_PROVISIONING_PATH, Some(headers), "provisioning").await
}

/// Open an authenticated chat WebSocket. Headers carry the device's ACI +
/// device id + password; the returned receiver surfaces server-pushed events
/// (incoming messages, alerts, etc.) for the caller to dispatch.
pub async fn connect_chat_authenticated(
    env_kind: Environment,
    auth: AuthenticatedChatHeaders,
) -> Result<(ChatConnection, mpsc::UnboundedReceiver<ws::ListenerEvent>), NetError> {
    debug!("connect_chat_authenticated: env={:?}", env_kind);
    connect_endpoint(
        env_kind,
        CHAT_WEBSOCKET_PATH,
        Some(ChatHeaders::Auth(auth)),
        "auth-chat",
    )
    .await
}

/// Open an unauthenticated chat WebSocket. Used by send paths that need
/// to fetch a recipient's prekey bundle. Per-request authorization
/// (access key / group token) is set on the individual requests; the
/// connection itself reveals no sender identity.
pub async fn connect_chat_unauthenticated(
    env_kind: Environment,
) -> Result<(ChatConnection, mpsc::UnboundedReceiver<ws::ListenerEvent>), NetError> {
    debug!("connect_chat_unauthenticated: env={:?}", env_kind);
    let headers = ChatHeaders::Unauth(UnauthenticatedChatHeaders {
        languages: Default::default(),
    });
    connect_endpoint(env_kind, CHAT_WEBSOCKET_PATH, Some(headers), "unauth-chat").await
}
