//! Plotly chart types for data visualisation
//!
//! Shared Plotly types used across analysis modules for generating
//! interactive charts compatible with Plotly.js.

use super::ProtocolType;
use serde::Serialize;

// ============================================================================
// Font and Styling Types
// ============================================================================

/// Plotly font configuration for titles, labels, and annotations
#[derive(Debug, Clone, Serialize, Default)]
pub struct PlotlyFont {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
}

/// Plotly legend configuration
#[derive(Debug, Clone, Serialize, Default)]
pub struct PlotlyLegend {
    /// Legend orientation: "v" (vertical) or "h" (horizontal)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orientation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<f64>,
    /// Horizontal anchor: "left", "center", "right", "auto"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xanchor: Option<String>,
}

/// Plotly annotation for adding text boxes and labels to charts
#[derive(Debug, Clone, Serialize)]
pub struct PlotlyAnnotation {
    pub text: String,
    /// Reference for x position: "paper" (0-1 fraction) or "x" (data coords)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xref: Option<String>,
    /// Reference for y position: "paper" (0-1 fraction) or "y" (data coords)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xanchor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yanchor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub showarrow: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bgcolor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bordercolor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub borderwidth: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub borderpad: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub font: Option<PlotlyFont>,
}

impl PlotlyAnnotation {
    /// Create a statistics box annotation (common pattern for summary stats)
    ///
    /// Positioned in paper coordinates with monospace font and subtle border.
    pub fn stats_box(text: &str, x: f64, y: f64) -> Self {
        Self {
            text: text.to_string(),
            xref: Some("paper".to_string()),
            yref: Some("paper".to_string()),
            x: Some(x),
            y: Some(y),
            xanchor: Some("left".to_string()),
            yanchor: Some("bottom".to_string()),
            showarrow: Some(false),
            bgcolor: Some("rgba(255, 255, 255, 0.8)".to_string()),
            bordercolor: Some("gray".to_string()),
            borderwidth: Some(1),
            borderpad: Some(4),
            font: Some(PlotlyFont {
                family: Some("monospace".to_string()),
                size: Some(10),
            }),
        }
    }
}

// ============================================================================
// Chart Types
// ============================================================================

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
    /// Stack group for stacked area charts (e.g., "one")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stackgroup: Option<String>,
    /// Fill mode for area charts (e.g., "tonexty", "tozeroy")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fill: Option<String>,
    /// Fill colour for area charts (e.g., "rgba(46, 204, 113, 0.7)")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fillcolor: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<f64>,
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
    /// Interactive control menus (e.g., linear/log toggle buttons)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updatemenus: Option<Vec<PlotlyUpdateMenu>>,
    /// Legend configuration (position, orientation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legend: Option<PlotlyLegend>,
    /// Annotations (text boxes, labels, stats boxes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Vec<PlotlyAnnotation>>,
}

/// Plotly title configuration
#[derive(Debug, Clone, Serialize)]
pub struct PlotlyTitle {
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub font: Option<PlotlyFont>,
}

/// Plotly axis configuration
#[derive(Debug, Clone, Serialize)]
pub struct PlotlyAxis {
    pub title: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub axis_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tickangle: Option<i32>,
    /// Fixed axis range (e.g., [0, 100] for percentage axes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<Vec<f64>>,
    /// Suffix to append to tick labels (e.g., "%" for percentages)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticksuffix: Option<String>,
}

/// Plotly secondary axis configuration
#[derive(Debug, Clone, Serialize)]
pub struct PlotlySecondaryAxis {
    pub title: String,
    pub overlaying: String,
    pub side: String,
}

/// Plotly update menu (buttons for interactive controls)
#[derive(Debug, Clone, Serialize)]
pub struct PlotlyUpdateMenu {
    #[serde(rename = "type")]
    pub menu_type: String,
    pub direction: String,
    pub x: f64,
    pub y: f64,
    pub buttons: Vec<PlotlyButton>,
}

/// Plotly button for update menus
#[derive(Debug, Clone, Serialize)]
pub struct PlotlyButton {
    pub label: String,
    pub method: String,
    pub args: Vec<serde_json::Value>,
}

impl PlotlyLayout {
    /// Create a basic layout with single y-axis
    pub fn basic(title: &str, x_title: &str, y_title: &str) -> Self {
        Self {
            title: PlotlyTitle {
                text: title.to_string(),
                font: None,
            },
            xaxis: PlotlyAxis {
                title: x_title.to_string(),
                axis_type: None,
                tickangle: None,
                range: None,
                ticksuffix: None,
            },
            yaxis: PlotlyAxis {
                title: y_title.to_string(),
                axis_type: None,
                tickangle: None,
                range: None,
                ticksuffix: None,
            },
            yaxis2: None,
            hovermode: "x unified".to_string(),
            hoverlabel: PlotlyHoverLabel { namelength: -1 },
            bargap: None,
            barmode: None,
            updatemenus: None,
            legend: None,
            annotations: None,
        }
    }

    /// Create a layout with dual y-axes
    pub fn dual_axis(title: &str, x_title: &str, y1_title: &str, y2_title: &str) -> Self {
        Self {
            title: PlotlyTitle {
                text: title.to_string(),
                font: None,
            },
            xaxis: PlotlyAxis {
                title: x_title.to_string(),
                axis_type: None,
                tickangle: None,
                range: None,
                ticksuffix: None,
            },
            yaxis: PlotlyAxis {
                title: y1_title.to_string(),
                axis_type: None,
                tickangle: None,
                range: None,
                ticksuffix: None,
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
            updatemenus: None,
            legend: None,
            annotations: None,
        }
    }

    /// Add linear/log toggle buttons to the layout
    pub fn with_log_toggle(mut self) -> Self {
        self.updatemenus = Some(vec![PlotlyUpdateMenu {
            menu_type: "buttons".to_string(),
            direction: "left".to_string(),
            x: 0.0,
            y: 1.15,
            buttons: vec![
                PlotlyButton {
                    label: "Linear".to_string(),
                    method: "relayout".to_string(),
                    args: vec![serde_json::json!({"yaxis.type": "linear"})],
                },
                PlotlyButton {
                    label: "Log".to_string(),
                    method: "relayout".to_string(),
                    args: vec![serde_json::json!({"yaxis.type": "log"})],
                },
            ],
        }]);
        self
    }

    /// Add legend configuration
    ///
    /// Standard positioning: `with_legend("v", 1.02, 1.0, "left")` for vertical legend on right
    pub fn with_legend(mut self, orientation: &str, x: f64, y: f64, xanchor: &str) -> Self {
        self.legend = Some(PlotlyLegend {
            orientation: Some(orientation.to_string()),
            x: Some(x),
            y: Some(y),
            xanchor: Some(xanchor.to_string()),
        });
        self
    }

    /// Add annotations to the layout
    pub fn with_annotations(mut self, annotations: Vec<PlotlyAnnotation>) -> Self {
        self.annotations = Some(annotations);
        self
    }

    /// Set title font size
    pub fn with_title_font_size(mut self, size: u32) -> Self {
        self.title.font = Some(PlotlyFont {
            family: None,
            size: Some(size),
        });
        self
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
            stackgroup: None,
            fill: None,
            fillcolor: None,
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
                width: None,
            }),
            visible: None,
            text: None,
            textposition: None,
            hovertemplate: None,
            stackgroup: None,
            fill: None,
            fillcolor: None,
        }
    }

    /// Create a stacked area trace with custom fill colour
    ///
    /// Used for charts like spendability distribution where each area needs
    /// a distinct semi-transparent fill colour.
    pub fn stacked_area_with_fill(
        x: Vec<String>,
        y: Vec<f64>,
        name: &str,
        line_color: &str,
        fill_color: &str,
    ) -> Self {
        Self {
            x,
            y,
            name: name.to_string(),
            trace_type: "scatter".to_string(),
            mode: Some("lines".to_string()),
            yaxis: None,
            marker: None,
            line: Some(PlotlyLine {
                color: line_color.to_string(),
                width: Some(0.0), // No visible line, just the fill
            }),
            visible: None,
            text: None,
            textposition: None,
            hovertemplate: None,
            stackgroup: Some("one".to_string()),
            fill: Some("tonexty".to_string()),
            fillcolor: Some(fill_color.to_string()),
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

    /// Configure trace for stacked area chart
    ///
    /// Sets stackgroup to "one" and fill to "tonexty" for proper Plotly stacked area rendering.
    pub fn stacked_area(mut self) -> Self {
        self.stackgroup = Some("one".to_string());
        self.fill = Some("tonexty".to_string());
        self
    }

    /// Set custom fill colour for area charts
    pub fn with_fillcolor(mut self, color: &str) -> Self {
        self.fillcolor = Some(color.to_string());
        self
    }

    /// Set fill to start from zero (for first trace in stacked area)
    pub fn fill_to_zero(mut self) -> Self {
        self.fill = Some("tozeroy".to_string());
        self
    }
}

/// Get colour for a protocol type (consistent with visualisation/export.py)
pub fn get_protocol_colour(protocol: ProtocolType) -> &'static str {
    match protocol {
        ProtocolType::BitcoinStamps => "#E74C3C",
        ProtocolType::Counterparty => "#3498DB",
        ProtocolType::OmniLayer => "#9B59B6",
        ProtocolType::LikelyLegitimateMultisig => "#2ECC71",
        ProtocolType::DataStorage => "#F39C12",
        ProtocolType::Chancecoin => "#1ABC9C",
        ProtocolType::AsciiIdentifierProtocols => "#E67E22",
        ProtocolType::PPk => "#16A085",
        ProtocolType::OpReturnSignalled => "#BB3A00",
        ProtocolType::LikelyDataStorage => "#D35400",
        ProtocolType::Unknown => "#95A5A6",
    }
}

/// Get colour for a Bitcoin Stamps variant name
///
/// Used for stacked area charts showing variant distribution over time.
pub fn get_stamps_variant_colour(variant: &str) -> &'static str {
    match variant {
        "Classic" => "#E74C3C",    // Red (same as BitcoinStamps protocol)
        "SRC-20" => "#3498DB",     // Blue
        "SRC-721" => "#9B59B6",    // Purple
        "SRC-101" => "#2ECC71",    // Green
        "HTML" => "#F39C12",       // Orange
        "Compressed" => "#1ABC9C", // Teal
        "Data" => "#E67E22",       // Dark orange
        "Unknown" => "#95A5A6",    // Grey
        _ => "#CCCCCC",            // Default fallback
    }
}
