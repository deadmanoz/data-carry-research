//! Plotly chart types for data visualisation
//!
//! Shared Plotly types used across analysis modules for generating
//! interactive charts compatible with Plotly.js.

use serde::Serialize;

/// Complete Plotly chart data structure
///
/// Standard format expected by Plotly.js: `{data: [...], layout: {...}}`
#[derive(Debug, Clone, Serialize)]
pub struct PlotlyChart {
    pub data: Vec<PlotlyTrace>,
    pub layout: PlotlyLayout,
}

/// Plotly trace configuration
///
/// Represents a single data series in the chart.
#[derive(Debug, Clone, Serialize)]
pub struct PlotlyTrace {
    pub x: Vec<String>,
    pub y: Vec<f64>,
    pub name: String,
    #[serde(rename = "type")]
    pub trace_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yaxis: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marker: Option<PlotlyMarker>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<PlotlyLine>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visible: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub textposition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hovertemplate: Option<String>,
}

/// Plotly marker configuration
#[derive(Debug, Clone, Serialize)]
pub struct PlotlyMarker {
    pub color: String,
}

/// Plotly line configuration
#[derive(Debug, Clone, Serialize)]
pub struct PlotlyLine {
    pub color: String,
}

/// Plotly hover label configuration
#[derive(Debug, Clone, Serialize)]
pub struct PlotlyHoverLabel {
    /// -1 means show full name without truncation
    pub namelength: i32,
}

/// Plotly layout configuration
#[derive(Debug, Clone, Serialize)]
pub struct PlotlyLayout {
    pub title: PlotlyTitle,
    pub xaxis: PlotlyAxis,
    pub yaxis: PlotlyAxis,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yaxis2: Option<PlotlySecondaryAxis>,
    pub hovermode: String,
    pub hoverlabel: PlotlyHoverLabel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bargap: Option<f64>,
    /// Bar mode: "stack", "group", "overlay", "relative"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub barmode: Option<String>,
}

/// Plotly title configuration
#[derive(Debug, Clone, Serialize)]
pub struct PlotlyTitle {
    pub text: String,
}

/// Plotly axis configuration
#[derive(Debug, Clone, Serialize)]
pub struct PlotlyAxis {
    pub title: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub axis_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tickangle: Option<i32>,
}

/// Plotly secondary axis configuration
#[derive(Debug, Clone, Serialize)]
pub struct PlotlySecondaryAxis {
    pub title: String,
    pub overlaying: String,
    pub side: String,
}

impl PlotlyLayout {
    /// Create a basic layout with single y-axis
    pub fn basic(title: &str, x_title: &str, y_title: &str) -> Self {
        Self {
            title: PlotlyTitle {
                text: title.to_string(),
            },
            xaxis: PlotlyAxis {
                title: x_title.to_string(),
                axis_type: None,
                tickangle: None,
            },
            yaxis: PlotlyAxis {
                title: y_title.to_string(),
                axis_type: None,
                tickangle: None,
            },
            yaxis2: None,
            hovermode: "x unified".to_string(),
            hoverlabel: PlotlyHoverLabel { namelength: -1 },
            bargap: None,
            barmode: None,
        }
    }

    /// Create a layout with dual y-axes
    pub fn dual_axis(title: &str, x_title: &str, y1_title: &str, y2_title: &str) -> Self {
        Self {
            title: PlotlyTitle {
                text: title.to_string(),
            },
            xaxis: PlotlyAxis {
                title: x_title.to_string(),
                axis_type: None,
                tickangle: None,
            },
            yaxis: PlotlyAxis {
                title: y1_title.to_string(),
                axis_type: None,
                tickangle: None,
            },
            yaxis2: Some(PlotlySecondaryAxis {
                title: y2_title.to_string(),
                overlaying: "y".to_string(),
                side: "right".to_string(),
            }),
            hovermode: "x unified".to_string(),
            hoverlabel: PlotlyHoverLabel { namelength: -1 },
            bargap: None,
            barmode: None,
        }
    }
}

impl PlotlyTrace {
    /// Create a bar trace
    pub fn bar(x: Vec<String>, y: Vec<f64>, name: &str, color: &str) -> Self {
        Self {
            x,
            y,
            name: name.to_string(),
            trace_type: "bar".to_string(),
            mode: None,
            yaxis: None,
            marker: Some(PlotlyMarker {
                color: color.to_string(),
            }),
            line: None,
            visible: None,
            text: None,
            textposition: None,
            hovertemplate: None,
        }
    }

    /// Create a line trace
    pub fn line(x: Vec<String>, y: Vec<f64>, name: &str, color: &str) -> Self {
        Self {
            x,
            y,
            name: name.to_string(),
            trace_type: "scatter".to_string(),
            mode: Some("lines+markers".to_string()),
            yaxis: None,
            marker: None,
            line: Some(PlotlyLine {
                color: color.to_string(),
            }),
            visible: None,
            text: None,
            textposition: None,
            hovertemplate: None,
        }
    }

    /// Set this trace to use the secondary y-axis
    pub fn on_secondary_axis(mut self) -> Self {
        self.yaxis = Some("y2".to_string());
        self
    }

    /// Set this trace to be hidden by default (toggle via legend)
    pub fn hidden_by_default(mut self) -> Self {
        self.visible = Some("legendonly".to_string());
        self
    }
}

/// Get colour for a protocol name (consistent with visualisation/export.py)
pub fn get_protocol_colour(protocol: &str) -> &'static str {
    match protocol {
        "BitcoinStamps" => "#E74C3C",
        "Counterparty" => "#3498DB",
        "OmniLayer" => "#9B59B6",
        "LikelyLegitimateMultisig" => "#2ECC71",
        "DataStorage" => "#F39C12",
        "Chancecoin" => "#1ABC9C",
        "AsciiIdentifierProtocols" => "#E67E22",
        "PPk" => "#16A085",
        "OpReturnSignalled" => "#BB3A00",
        "LikelyDataStorage" => "#D35400",
        "Unknown" => "#95A5A6",
        _ => "#CCCCCC",
    }
}
