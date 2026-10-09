"""
HTML email body formatter for IntelliShield SDN attack alert emails.

Produces clean, readable HTML emails with attack details, severity badges,
and detection pipeline metadata.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from shared_contracts.models import AlertEvent


def _severity_color(severity: str) -> str:
    """Map severity label to a hex color for the email badge."""
    s = str(severity).upper()
    if s == "CRITICAL":
        return "#dc2626"
    if s == "HIGH":
        return "#ea580c"
    if s == "MEDIUM":
        return "#d97706"
    if s == "LOW":
        return "#2563eb"
    return "#6b7280"


def _safe_str(val: Any, default: str = "N/A") -> str:
    if val is None:
        return default
    return str(val)


def format_attack_subject(alert: AlertEvent) -> str:
    """Build email subject line from alert."""
    sev = str(getattr(alert.severity, "value", alert.severity)).upper()
    return f"[IntelliShield] {sev} — {alert.title}"


def format_attack_html(alert: AlertEvent) -> str:
    """Build a professional HTML email body from an AlertEvent."""
    sev_str = str(getattr(alert.severity, "value", alert.severity)).upper()
    sev_color = _severity_color(sev_str)
    atype = str(getattr(alert.alert_type, "value", alert.alert_type))
    ev = alert.evidence or {}

    # Extract fields from evidence
    attack_hint = _safe_str(ev.get("attack_hint") or ev.get("attack_type_hint"))
    detector_path = _safe_str(ev.get("detector_path"))
    fusion_linked = ev.get("fusion_linked", False)
    correlation_linked = ev.get("correlation_linked", False)
    rca_linked = ev.get("rca_linked", False)
    fused_decision = _safe_str(ev.get("fused_decision"))
    fused_confidence = ev.get("fused_confidence")

    timestamp = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if alert.timestamp else "Unknown"

    rows = [
        ("Alert ID", f"<code>{alert.alert_id}</code>"),
        ("Timestamp", timestamp),
        ("Severity", f'<span style="background:{sev_color};color:#fff;padding:2px 8px;border-radius:4px;font-weight:bold;">{sev_str}</span>'),
        ("Alert Type", atype),
        ("Attack Classification", attack_hint),
        ("Detection Source", detector_path),
        ("Event ID", _safe_str(alert.event_id)),
    ]

    if fusion_linked:
        rows.append(("R6 Fusion Decision", fused_decision))
        if fused_confidence is not None:
            rows.append(("Fusion Confidence", f"{fused_confidence}"))
        rows.append(("Fusion ID", _safe_str(ev.get("fusion_id"))))

    if correlation_linked:
        rows.append(("R4 Correlation", _safe_str(ev.get("correlation_id"))))
        rows.append(("Correlation Score", _safe_str(ev.get("correlation_score"))))

    if rca_linked and alert.rca_report_id:
        rows.append(("R5 RCA Report", f"<code>{alert.rca_report_id}</code>"))

    rows.append(("Source Module", _safe_str(alert.source)))
    rows.append(("Message", alert.message or "—"))

    table_rows = "\n".join(
        f'        <tr><td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-weight:600;width:180px;color:#374151;">{label}</td>'
        f'<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;">{value}</td></tr>'
        for label, value in rows
    )

    return f"""\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:20px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f9fafb;color:#111827;">
  <div style="max-width:640px;margin:0 auto;">
    <div style="background:linear-gradient(135deg,#1e293b,#0f172a);color:#f8fafc;padding:20px 24px;border-radius:8px 8px 0 0;">
      <h1 style="margin:0;font-size:20px;">🛡️ IntelliShield SDN — Attack Alert</h1>
      <p style="margin:6px 0 0;font-size:13px;color:#94a3b8;">Automated notification from R6 Fusion → R7 Verification pipeline</p>
    </div>
    <div style="background:#fff;border:1px solid #e5e7eb;border-top:none;border-radius:0 0 8px 8px;overflow:hidden;">
      <table style="width:100%;border-collapse:collapse;font-size:14px;">
{table_rows}
      </table>
    </div>
    <p style="text-align:center;font-size:11px;color:#9ca3af;margin-top:16px;">
      This is an automated alert from IntelliShield SDN. Do not reply to this email.
    </p>
  </div>
</body>
</html>"""


def format_recovery_subject(alert: AlertEvent) -> str:
    """Build recovery email subject."""
    return f"[IntelliShield] RECOVERY — {alert.title}"


def format_recovery_html(alert: AlertEvent) -> str:
    """Build a recovery notification email body."""
    timestamp = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if alert.timestamp else "Unknown"
    return f"""\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:20px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f9fafb;color:#111827;">
  <div style="max-width:640px;margin:0 auto;">
    <div style="background:linear-gradient(135deg,#065f46,#064e3b);color:#f8fafc;padding:20px 24px;border-radius:8px 8px 0 0;">
      <h1 style="margin:0;font-size:20px;">✅ IntelliShield SDN — Attack Recovered</h1>
      <p style="margin:6px 0 0;font-size:13px;color:#a7f3d0;">Threat cleared — normal traffic pattern restored</p>
    </div>
    <div style="background:#fff;border:1px solid #e5e7eb;border-top:none;border-radius:0 0 8px 8px;padding:20px 24px;">
      <p style="font-size:14px;line-height:1.6;">
        The previously detected attack (<strong>{alert.title}</strong>) has been resolved.<br>
        Alert ID: <code>{alert.alert_id}</code><br>
        Original time: {timestamp}<br>
        The system has returned to normal monitoring.
      </p>
    </div>
    <p style="text-align:center;font-size:11px;color:#9ca3af;margin-top:16px;">
      This is an automated recovery notification from IntelliShield SDN.
    </p>
  </div>
</body>
</html>"""
