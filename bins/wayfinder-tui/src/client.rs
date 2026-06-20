//! Minimal TCP client for the Wayfinder management API.
//!
//! Mirrors the server side in `wayfinder-server`: requests and responses are
//! prost-encoded [`WayfinderRequest`]/[`WayfinderResponse`] messages carried
//! over a TCP stream with 4-byte big-endian length-delimited framing.

use std::net::SocketAddr;

use anyhow::{Context, anyhow};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use prost::Message;
use tokio::net::TcpStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use wayfinder_protos::wayfinder_v1alpha::{
    GetLinkQualityTableRequest, GetMetricsRequest, GetNodeInfoRequest, GetOgmScheduleRequest,
    GetRoutingTableRequest, GetThroughputRequest, LinkQualityTable, NodeInfo, NodeMetrics,
    OgmSchedule, RoutingTable, Throughput, WayfinderRequest, WayfinderResponse,
    wayfinder_request::Request as RequestKind, wayfinder_response::Response as ResponseKind,
};

/// A connected management-API client over a single TCP stream.
pub struct Client {
    framed: Framed<TcpStream, LengthDelimitedCodec>,
}

impl Client {
    /// Open a TCP connection to the management API at `addr`.
    pub async fn connect(addr: SocketAddr) -> anyhow::Result<Self> {
        let stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("connecting to {addr}"))?;
        let framed = LengthDelimitedCodec::builder().new_framed(stream);
        Ok(Self { framed })
    }

    /// Encode and send one request, then await and decode the single response.
    async fn request(&mut self, request: RequestKind) -> anyhow::Result<ResponseKind> {
        let envelope = WayfinderRequest {
            request: Some(request),
        };
        let mut buf = Vec::new();
        envelope.encode(&mut buf)?;
        self.framed.send(Bytes::from(buf)).await?;

        let frame = self
            .framed
            .next()
            .await
            .ok_or_else(|| anyhow!("connection closed by server"))??;
        let response = WayfinderResponse::decode(frame)?;
        response
            .response
            .ok_or_else(|| anyhow!("server returned an empty response envelope"))
    }

    /// Query basic identity and capacity information for the node.
    pub async fn node_info(&mut self) -> anyhow::Result<NodeInfo> {
        match self
            .request(RequestKind::GetNodeInfo(GetNodeInfoRequest {}))
            .await?
        {
            ResponseKind::NodeInfo(info) => Ok(info),
            other => Err(unexpected("NodeInfo", &other)),
        }
    }

    /// Query the full BATMAN originator (routing) table.
    pub async fn routing_table(&mut self) -> anyhow::Result<RoutingTable> {
        match self
            .request(RequestKind::GetRoutingTable(GetRoutingTableRequest {}))
            .await?
        {
            ResponseKind::RoutingTable(table) => Ok(table),
            other => Err(unexpected("RoutingTable", &other)),
        }
    }

    /// Query the per-(neighbor, interface) link-quality table.
    pub async fn link_quality_table(&mut self) -> anyhow::Result<LinkQualityTable> {
        match self
            .request(RequestKind::GetLinkQualityTable(
                GetLinkQualityTableRequest {},
            ))
            .await?
        {
            ResponseKind::LinkQualityTable(table) => Ok(table),
            other => Err(unexpected("LinkQualityTable", &other)),
        }
    }

    /// Query the current per-interface adaptive OGM emission schedule.
    pub async fn ogm_schedule(&mut self) -> anyhow::Result<OgmSchedule> {
        match self
            .request(RequestKind::GetOgmSchedule(GetOgmScheduleRequest {}))
            .await?
        {
            ResponseKind::OgmSchedule(schedule) => Ok(schedule),
            other => Err(unexpected("OgmSchedule", &other)),
        }
    }

    /// Query the current per-interface throughput estimates (smoothed
    /// bytes/sec and frames/sec per interface, plus node-wide totals).
    pub async fn throughput(&mut self) -> anyhow::Result<Throughput> {
        match self
            .request(RequestKind::GetThroughput(GetThroughputRequest {}))
            .await?
        {
            ResponseKind::Throughput(throughput) => Ok(throughput),
            other => Err(unexpected("Throughput", &other)),
        }
    }

    /// Query the node's aggregate health and topology metrics (uptime,
    /// neighbour count, table occupancy, TQ / path-diversity distribution).
    pub async fn node_metrics(&mut self) -> anyhow::Result<NodeMetrics> {
        match self
            .request(RequestKind::GetMetrics(GetMetricsRequest {}))
            .await?
        {
            ResponseKind::Metrics(metrics) => Ok(metrics),
            other => Err(unexpected("Metrics", &other)),
        }
    }
}

/// Build an error for a response variant that does not match the request.
fn unexpected(want: &str, got: &ResponseKind) -> anyhow::Error {
    let got = match got {
        ResponseKind::NodeInfo(_) => "NodeInfo",
        ResponseKind::RoutingTable(_) => "RoutingTable",
        ResponseKind::LinkQualityTable(_) => "LinkQualityTable",
        ResponseKind::ResolveRoute(_) => "ResolveRoute",
        ResponseKind::OgmSchedule(_) => "OgmSchedule",
        ResponseKind::Throughput(_) => "Throughput",
        ResponseKind::Metrics(_) => "Metrics",
        ResponseKind::Error(_) => "Error",
    };
    anyhow!("expected {want} response, got {got}")
}
