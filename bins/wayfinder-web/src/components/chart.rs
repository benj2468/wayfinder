//! The throughput trend chart.
//!
//! A two-series line chart drawn as inline SVG — no charting library, which
//! keeps the wasm bundle honest and means the marks obey the same design tokens
//! as everything else.
//!
//! # Choices worth knowing
//!
//! **One axis, not two.** Both series are bytes per second, so they share a
//! scale and are directly comparable. Two y-scales would let "sent" and
//! "received" cross at meaningless points and imply relationships that are not
//! there.
//!
//! **The scale starts at zero** and is driven by the largest sample in view. A
//! trend chart whose baseline floats makes a steady link look volatile.
//!
//! **Both series are named in a legend and direct-labelled with their current
//! value**, so identity never rests on colour alone — the reading survives
//! colour-blindness, a greyscale print, and forced-colors mode.
//!
//! The two hues are categorical slots 1 and 2 of the project palette, checked
//! for colour-blind separation against both the light and dark chart surfaces
//! (ΔE ≥ 24 protan/tritan in both, comfortably above the ΔE 8 target).

use std::collections::VecDeque;

use leptos::prelude::*;

use crate::format;
use crate::state::ThroughputSample;

/// Samples below which the chart declines to draw.
///
/// Two points make a line but not a trend, and a chart drawn through almost no
/// data invites conclusions it cannot support. Below this the panel says it is
/// still collecting.
const MIN_SAMPLES: usize = 2;

/// The plot's coordinate space. The SVG scales to its container via
/// `viewBox`/`preserveAspectRatio`, so these are aspect ratio rather than pixels.
const VIEW_W: f64 = 600.0;
/// Height of the plot's coordinate space.
const VIEW_H: f64 = 160.0;

/// Render the node-wide throughput trend.
#[component]
pub fn ThroughputChart(
    /// Samples oldest first, one per poll.
    #[prop(into)]
    samples: Signal<VecDeque<ThroughputSample>>,
) -> impl IntoView {
    view! {
        {move || {
            let samples: Vec<ThroughputSample> = samples.get().iter().copied().collect();
            if samples.len() < MIN_SAMPLES {
                return view! {
                    <p class="wf-empty">"Collecting samples for the trend…"</p>
                }
                    .into_any();
            }

            // A common ceiling for both series, rounded up off the largest
            // sample in view. `max(1.0)` keeps an all-idle mesh from dividing
            // by zero and drawing NaN paths.
            let peak = samples
                .iter()
                .map(|s| s.rx_bps.max(s.tx_bps))
                .fold(0.0_f64, f64::max)
                .max(1.0);

            let rx = polyline(&samples, peak, |s| s.rx_bps);
            let tx = polyline(&samples, peak, |s| s.tx_bps);
            let current = samples.last().copied().unwrap_or_default();

            view! {
                <div class="wf-chart">
                    <div class="wf-legend">
                        <span class="wf-legend-item">
                            <span class="wf-legend-mark wf-series-rx" />
                            "Received"
                            <span class="wf-legend-value wf-mono">
                                {format::rate(current.rx_bps)}
                            </span>
                        </span>
                        <span class="wf-legend-item">
                            <span class="wf-legend-mark wf-series-tx" />
                            "Sent"
                            <span class="wf-legend-value wf-mono">
                                {format::rate(current.tx_bps)}
                            </span>
                        </span>
                        <span class="wf-legend-peak">"peak " {format::rate(peak)}</span>
                    </div>

                    <svg
                        class="wf-chart-svg"
                        viewBox=format!("0 0 {VIEW_W} {VIEW_H}")
                        preserveAspectRatio="none"
                        role="img"
                        aria-label=format!(
                            "Throughput trend. Received now {}, sent now {}, peak {}.",
                            format::rate(current.rx_bps),
                            format::rate(current.tx_bps),
                            format::rate(peak),
                        )
                    >
                        // A recessive midline, so a reader can judge "about half
                        // of peak" without a full grid competing with the data.
                        <line
                            class="wf-chart-grid"
                            x1="0"
                            y1=VIEW_H / 2.0
                            x2=VIEW_W
                            y2=VIEW_H / 2.0
                        />
                        <line
                            class="wf-chart-axis"
                            x1="0"
                            y1=VIEW_H
                            x2=VIEW_W
                            y2=VIEW_H
                        />
                        <polyline class="wf-chart-line wf-series-rx-stroke" points=rx />
                        <polyline class="wf-chart-line wf-series-tx-stroke" points=tx />
                    </svg>
                </div>
            }
                .into_any()
        }}
    }
}

/// Project samples onto the plot as an SVG `points` list.
///
/// The y axis is inverted (SVG grows downward) and anchored at zero, so a
/// sample's height is its share of `peak` rather than its rank among its
/// neighbours.
fn polyline(
    samples: &[ThroughputSample],
    peak: f64,
    value: impl Fn(&ThroughputSample) -> f64,
) -> String {
    let last = (samples.len() - 1).max(1) as f64;
    samples
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let x = i as f64 / last * VIEW_W;
            let y = VIEW_H - (value(s) / peak).clamp(0.0, 1.0) * VIEW_H;
            format!("{x:.1},{y:.1}")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples(values: &[(f64, f64)]) -> Vec<ThroughputSample> {
        values
            .iter()
            .map(|&(rx_bps, tx_bps)| ThroughputSample { rx_bps, tx_bps })
            .collect()
    }

    #[test]
    fn polyline_anchors_the_scale_at_zero() {
        // A sample at the peak touches the top; a zero sample sits on the
        // baseline. Anything else means the baseline is floating.
        let s = samples(&[(0.0, 0.0), (100.0, 0.0)]);
        let points = polyline(&s, 100.0, |s| s.rx_bps);

        assert_eq!(points, format!("0.0,{VIEW_H:.1} {VIEW_W:.1},0.0"));
    }

    #[test]
    fn polyline_spreads_samples_across_the_full_width() {
        let s = samples(&[(1.0, 0.0), (1.0, 0.0), (1.0, 0.0)]);
        let points = polyline(&s, 1.0, |s| s.rx_bps);

        assert!(points.starts_with("0.0,"), "{points}");
        assert!(
            points.contains(&format!("{VIEW_W:.1},")),
            "the last sample reaches the right edge: {points}"
        );
    }

    #[test]
    fn polyline_clamps_a_sample_above_the_peak() {
        // The peak is computed across both series, so one series can legitimately
        // be asked to draw above its own max — it must not escape the viewBox.
        let s = samples(&[(0.0, 0.0), (500.0, 0.0)]);
        let points = polyline(&s, 100.0, |s| s.rx_bps);

        assert!(points.ends_with(",0.0"), "clamped to the top: {points}");
    }
}
