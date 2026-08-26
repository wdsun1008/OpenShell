// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Padding, Paragraph};

use super::sandbox_draft::wrap_value;
use crate::app::App;

fn push_field(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    value: &str,
    width: usize,
    label_style: Style,
    value_style: Style,
) {
    let label_width = Span::raw(label).width();
    if width <= label_width {
        lines.push(Line::from(Span::styled(label.to_string(), label_style)));
        for row in wrap_value(value, width.max(1)) {
            lines.push(Line::from(Span::styled(row, value_style)));
        }
        return;
    }
    let rows = wrap_value(value, width - label_width);
    for (index, row) in rows.into_iter().enumerate() {
        let prefix = if index == 0 {
            label.to_string()
        } else {
            " ".repeat(label_width)
        };
        lines.push(Line::from(vec![
            Span::styled(prefix, label_style),
            Span::styled(row, value_style),
        ]));
    }
}

pub fn draw(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    let t = &app.theme;
    let base_block = Block::default()
        .title(super::sandbox_settings::draw_policy_tab_title(app))
        .borders(Borders::ALL)
        .border_style(t.border_focused)
        .padding(Padding::horizontal(1));
    let inner = base_block.inner(area);
    let width = usize::from(inner.width);

    let lines: Vec<Line<'static>> = if app.sandbox_attestation_loading {
        vec![Line::from(Span::styled(
            "Requesting a fresh appraisal...",
            t.muted,
        ))]
    } else if let Some(appraisal) = &app.sandbox_attestation {
        let mut lines = Vec::new();
        push_field(
            &mut lines,
            "EAR status: ",
            &appraisal.ear_status,
            width,
            t.muted,
            t.text,
        );
        push_field(
            &mut lines,
            "Policy ID: ",
            &appraisal.policy_id,
            width,
            t.muted,
            t.text,
        );
        if let Some(vector) = &appraisal.ar4si_vector {
            push_field(
                &mut lines,
                "AR4SI vector: ",
                &format!(
                    "hardware={} executables={} configuration={} file-system={}",
                    vector.hardware, vector.executables, vector.configuration, vector.file_system
                ),
                width,
                t.muted,
                t.text,
            );
        }
        lines.push(Line::from(Span::styled("Measurements:", t.muted)));
        for measurement in &appraisal.measurements {
            let algorithm = if measurement.algorithm.is_empty() {
                "-"
            } else {
                &measurement.algorithm
            };
            let measured = if measurement.measurement.is_empty() {
                "-"
            } else {
                &measurement.measurement
            };
            lines.push(Line::from(Span::styled(
                format!("  {} ({algorithm})", measurement.component),
                t.heading,
            )));
            push_field(
                &mut lines,
                "    Measurement: ",
                measured,
                width,
                t.muted,
                t.text,
            );
            if measurement.references.is_empty() {
                push_field(&mut lines, "    Reference: ", "-", width, t.muted, t.text);
            } else {
                for reference in &measurement.references {
                    push_field(
                        &mut lines,
                        "    Reference: ",
                        reference,
                        width,
                        t.muted,
                        t.text,
                    );
                }
            }
        }
        lines
    } else {
        vec![Line::from(vec![
            Span::styled("Press ", t.muted),
            Span::styled("[r]", t.key_hint),
            Span::styled(" to request a fresh appraisal.", t.muted),
        ])]
    };

    let total_rows = lines.len();
    let paragraph = Paragraph::new(lines);
    let viewport_height = usize::from(inner.height);
    let max_scroll = total_rows.saturating_sub(viewport_height.max(1));
    app.trust_content_rows = total_rows;
    app.trust_viewport_height = viewport_height;
    app.trust_scroll = app.trust_scroll.min(max_scroll);

    let position = if total_rows == 0 {
        0
    } else {
        app.trust_scroll + 1
    };
    let scroll_info = format!(" [{position}/{total_rows}] ");
    let block =
        base_block.title_bottom(Line::from(Span::styled(scroll_info, t.muted)).right_aligned());
    let scroll = u16::try_from(app.trust_scroll).unwrap_or(u16::MAX);
    frame.render_widget(paragraph.block(block).scroll((scroll, 0)), area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_measurements_are_split_into_scrollable_rows() {
        let mut lines = Vec::new();
        push_field(
            &mut lines,
            "Measurement: ",
            &"ab".repeat(48),
            32,
            Style::default(),
            Style::default(),
        );
        assert!(lines.len() > 1);
        assert!(lines.iter().all(|line| line.width() <= 32));
        let rendered = lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert!(rendered.replace(' ', "").contains(&"ab".repeat(48)));
    }
}
