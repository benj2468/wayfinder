//! The dashboard's views.
//!
//! [`dashboard`] holds the shared reactive state and the polling loop;
//! [`widgets`] holds the presentational pieces the tabs share; everything else
//! is one tab. Tabs are pure functions of the dashboard state — they issue no
//! requests of their own, so switching tabs costs nothing and every tab is
//! always as fresh as every other.

pub mod chart;
pub mod dashboard;
pub mod link_quality;
pub mod links;
pub mod logo;
pub mod logs;
pub mod metrics;
pub mod overview;
pub mod routing;
pub mod security;
pub mod widgets;
