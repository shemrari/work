from html import escape
from io import BytesIO
import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy.orm import Session

from ...models import pydantic_models as models
from ...services.incident_reports import build_incident_report
from .. import dependencies

router = APIRouter(prefix="/reports", tags=["reports"])
logger = logging.getLogger(__name__)
UNAVAILABLE = "Not available in persisted data"


def _display(value: Any) -> str:
    if value is None or value == "":
        return UNAVAILABLE
    return str(value)


def _paragraph(value: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(_display(value)).replace("\n", "<br/>"), style)


def create_incident_pdf(report: Dict[str, Any]) -> bytes:
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=17 * mm,
        bottomMargin=17 * mm,
        title=f"Incident {report['incident']['id']} Cybersecurity Report",
        author="CyberSOC",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#12304A"),
        fontSize=19,
        leading=23,
        spaceAfter=5 * mm,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#12304A"),
        fontSize=12,
        leading=15,
        spaceBefore=4 * mm,
        spaceAfter=2 * mm,
    ))
    styles.add(ParagraphStyle(
        name="BodySmall",
        parent=styles["BodyText"],
        fontSize=8.5,
        leading=11,
        wordWrap="CJK",
    ))
    styles.add(ParagraphStyle(
        name="CellLabel",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#34495E"),
    ))
    styles.add(ParagraphStyle(
        name="LabBanner",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#7C2D12"),
    ))

    incident = report["incident"]
    story = [
        _paragraph("LAB SIMULATION ONLY", styles["LabBanner"]),
        Spacer(1, 3 * mm),
        _paragraph(f"Cybersecurity Incident Report · #{incident.get('id')}", styles["ReportTitle"]),
        _paragraph("This report uses persisted PostgreSQL incident, simulation, response-action, and original Wazuh alert records.", styles["BodySmall"]),
        Spacer(1, 2 * mm),
    ]

    story.append(_paragraph("Incident overview", styles["SectionHeading"]))
    overview_rows = [
        (_paragraph("Incident ID", styles["CellLabel"]), _paragraph(incident.get("id"), styles["BodySmall"])),
        (_paragraph("Title", styles["CellLabel"]), _paragraph(incident.get("title"), styles["BodySmall"])),
        (_paragraph("Severity", styles["CellLabel"]), _paragraph(incident.get("severity"), styles["BodySmall"])),
        (_paragraph("Status", styles["CellLabel"]), _paragraph(incident.get("status"), styles["BodySmall"])),
        (_paragraph("Source", styles["CellLabel"]), _paragraph(incident.get("source"), styles["BodySmall"])),
        (_paragraph("Detected at", styles["CellLabel"]), _paragraph(incident.get("detected_at"), styles["BodySmall"])),
        (_paragraph("AI anomaly score", styles["CellLabel"]), _paragraph(incident.get("anomaly_score"), styles["BodySmall"])),
        (_paragraph("AI anomaly status", styles["CellLabel"]), _paragraph(report.get("ai_anomaly_status"), styles["BodySmall"])),
        (_paragraph("Wazuh alert ID", styles["CellLabel"]), _paragraph(incident.get("wazuh_alert_id"), styles["BodySmall"])),
        (_paragraph("Wazuh rule ID", styles["CellLabel"]), _paragraph(report.get("wazuh_rule_id"), styles["BodySmall"])),
        (_paragraph("Wazuh rule level", styles["CellLabel"]), _paragraph(report.get("wazuh_rule_level"), styles["BodySmall"])),
        (_paragraph("Wazuh description", styles["CellLabel"]), _paragraph(report.get("wazuh_description"), styles["BodySmall"])),
        (_paragraph("Agent / target", styles["CellLabel"]), _paragraph(report.get("agent_target"), styles["BodySmall"])),
        (_paragraph("Incident details", styles["CellLabel"]), _paragraph(incident.get("description"), styles["BodySmall"])),
    ]
    overview = Table(overview_rows, colWidths=[42 * mm, 132 * mm], repeatRows=0, hAlign="LEFT")
    overview.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EEF3F7")),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(overview)

    story.append(_paragraph("Response actions", styles["SectionHeading"]))
    response_actions = report.get("response_actions") or []
    if response_actions:
        action_rows = [["Action", "Target", "Status / result", "Executed at", "Details"]]
        for action in response_actions:
            action_rows.append([
                _paragraph(action.get("action_type"), styles["BodySmall"]),
                _paragraph(action.get("target"), styles["BodySmall"]),
                _paragraph(f"{action.get('status')} / {action.get('result')}", styles["BodySmall"]),
                _paragraph(action.get("executed_at"), styles["BodySmall"]),
                _paragraph(action.get("description"), styles["BodySmall"]),
            ])
        actions_table = Table(action_rows, colWidths=[25 * mm, 27 * mm, 31 * mm, 34 * mm, 57 * mm], repeatRows=1)
        actions_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DCE7EF")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD5E1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(actions_table)
    else:
        story.append(_paragraph("No response actions are persisted for this incident.", styles["BodySmall"]))

    story.append(_paragraph("Timeline", styles["SectionHeading"]))
    timeline = report.get("timeline") or []
    if timeline:
        timeline_rows = [["Timestamp", "Event", "Details", "Reference"]]
        for event in timeline:
            timeline_rows.append([
                _paragraph(event.get("timestamp"), styles["BodySmall"]),
                _paragraph(event.get("event"), styles["BodySmall"]),
                _paragraph(event.get("description"), styles["BodySmall"]),
                _paragraph(event.get("reference"), styles["BodySmall"]),
            ])
        timeline_table = Table(timeline_rows, colWidths=[36 * mm, 34 * mm, 77 * mm, 27 * mm], repeatRows=1)
        timeline_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DCE7EF")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD5E1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(timeline_table)
    else:
        story.append(_paragraph("No timeline events are persisted for this incident.", styles["BodySmall"]))

    story.append(_paragraph("Related lab simulations", styles["SectionHeading"]))
    simulations = report.get("simulations") or []
    if simulations:
        simulation_rows = [["Run", "Scenario", "Target", "Status", "Attempts", "Wazuh result"]]
        for run in simulations:
            simulation_rows.append([
                _paragraph(run.get("id"), styles["BodySmall"]),
                _paragraph(run.get("scenario"), styles["BodySmall"]),
                _paragraph(run.get("target"), styles["BodySmall"]),
                _paragraph(run.get("status"), styles["BodySmall"]),
                _paragraph(run.get("attempt_count"), styles["BodySmall"]),
                _paragraph(f"{run.get('wazuh_status')} · {run.get('wazuh_alert_id') or UNAVAILABLE}", styles["BodySmall"]),
            ])
        simulations_table = Table(simulation_rows, colWidths=[13 * mm, 31 * mm, 30 * mm, 20 * mm, 18 * mm, 62 * mm], repeatRows=1)
        simulations_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DCE7EF")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD5E1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(simulations_table)
    else:
        story.append(_paragraph("No simulation run with a matching persisted Wazuh alert ID was found.", styles["BodySmall"]))

    story.extend([
        Spacer(1, 5 * mm),
        _paragraph(
            "LAB SIMULATION ONLY. Any listed response actions are simulations recorded for audit. "
            "No real firewall, network, operating-system, or host command was executed.",
            styles["BodySmall"],
        ),
    ])
    document.build(story)
    return buffer.getvalue()


@router.get("/incidents/{incident_id}", response_model=models.IncidentReportResponse)
def get_incident_report(incident_id: int, db: Session = Depends(dependencies.get_db)):
    try:
        return build_incident_report(incident_id, db)
    except LookupError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@router.get("/incidents/{incident_id}/pdf")
def export_incident_report_pdf(incident_id: int, db: Session = Depends(dependencies.get_db)):
    try:
        report = build_incident_report(incident_id, db)
        pdf_bytes = create_incident_pdf(report)
    except LookupError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except Exception as error:
        logger.exception("Failed to generate incident PDF report")
        raise HTTPException(status_code=500, detail="Failed to generate incident PDF") from error

    filename = f"cybersoc-incident-{incident_id}-report.pdf"
    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
