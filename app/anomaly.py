"""Anomaly detection and compliance scoring for APAAR Verify."""

from __future__ import annotations

from math import sqrt
from typing import Any, Dict, List, Optional

from sklearn.ensemble import IsolationForest
from sqlmodel import Session, delete, select

from app.models import AnomalyAlert, Institution, Program, Setting, Student, ValidationFlag


def _setting_value(session: Session, key: str, default: str) -> float:
    statement = select(Setting).where(Setting.key == key)
    setting = session.exec(statement).first()
    if setting is None:
        return float(default)
    try:
        return float(setting.value)
    except (TypeError, ValueError):
        return float(default)


def _institute_summary(session: Session, institution_id: int) -> Dict[str, float]:
    programs = session.exec(select(Program).where(Program.institution_id == institution_id)).all()
    total_intake = sum(int(p.approved_intake or 0) for p in programs)

    students = session.exec(
        select(Student).where(Student.institution_id == institution_id, Student.status == "ACTIVE")
    ).all()
    total_students = len(students)
    fill_ratio = (total_students / total_intake) if total_intake else 0.0
    enrolment_by_program: Dict[int, int] = {}
    for student in students:
        enrolment_by_program[student.program_id] = enrolment_by_program.get(student.program_id, 0) + 1
    max_program_fill_ratio = max(
        (
            enrolment_by_program.get(program.id, 0) / program.approved_intake
            for program in programs
            if program.approved_intake > 0
        ),
        default=0.0,
    )

    yearly_enrolment: Dict[int, int] = {}
    for student in students:
        yearly_enrolment[student.admission_year] = yearly_enrolment.get(student.admission_year, 0) + 1
    years = sorted(yearly_enrolment)
    yoy_growth = 0.0
    if len(years) >= 2 and yearly_enrolment[years[-2]]:
        yoy_growth = yearly_enrolment[years[-1]] / yearly_enrolment[years[-2]]

    nri_share = 0.0
    fn_share = 0.0
    oci_share = 0.0
    if total_students:
        nri_share = sum(1 for s in students if s.is_nri) / total_students
        fn_share = sum(1 for s in students if s.is_foreign_national) / total_students
        oci_share = sum(1 for s in students if s.oci_status) / total_students

    return {
        "fill_ratio": fill_ratio,
        "max_program_fill_ratio": max_program_fill_ratio,
        "nri_share": nri_share,
        "fn_share": fn_share,
        "oci_share": oci_share,
        "yoy_growth": yoy_growth,
        "total_students": total_students,
        "approved_intake": total_intake,
    }


def _zscore(value: float, values: List[float]) -> float:
    if not values:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    std_dev = sqrt(variance)
    if std_dev == 0:
        return 0.0
    return (value - mean) / std_dev


def _make_alert(session: Session, institution_id: int, code: str, score: float, reason: str) -> AnomalyAlert:
    alert = AnomalyAlert(
        institution_id=institution_id,
        code=code,
        score=float(score),
        reason=reason,
    )
    session.add(alert)
    return alert


def run_anomaly_detection(session: Session) -> List[AnomalyAlert]:
    """Generate A1-A5 anomaly alerts based on institutional risk signals."""
    session.exec(delete(AnomalyAlert))
    institutions = session.exec(select(Institution)).all()
    alerts: List[AnomalyAlert] = []

    if not institutions:
        return alerts

    metrics = {
        inst.id: _institute_summary(session, inst.id)
        for inst in institutions
    }
    fill_values = [m["fill_ratio"] for m in metrics.values()]
    nri_values = [m["nri_share"] for m in metrics.values()]
    fn_values = [m["fn_share"] for m in metrics.values()]
    oci_values = [m["oci_share"] for m in metrics.values()]
    # A1: fill ratio spike / intake overload
    for institution in institutions:
        metric = metrics[institution.id]
        z = _zscore(metric["fill_ratio"], fill_values)
        if abs(z) > 2 or metric["fill_ratio"] > 1.0 or metric["max_program_fill_ratio"] > 1.0:
            alerts.append(
                _make_alert(
                    session,
                    institution.id,
                    "A1",
                    max(abs(z), metric["max_program_fill_ratio"]),
                    f"Institution enrollment is {metric['fill_ratio']:.2%} of total approved intake; its highest program fill is {metric['max_program_fill_ratio']:.2%}. Review programs exceeding approved seats.",
                )
            )

    # A2: year-on-year surge
    surge_threshold = _setting_value(session, "yoy_surge_threshold", "2.00")
    for institution in institutions:
        metric = metrics[institution.id]
        if metric["yoy_growth"] > surge_threshold:
            alerts.append(
                _make_alert(
                    session,
                    institution.id,
                    "A2",
                    metric["yoy_growth"],
                    f"Enrollment grew {metric['yoy_growth']:.2f}x year-over-year, above the configured {surge_threshold:.2f}x threshold. Recommended action: review the new intake against approved capacity.",
                )
            )

    # A3: NRI / FN / OCI share outliers
    nri_threshold = _setting_value(session, "nri_outlier_threshold", "0.25")
    institutions_by_type: Dict[str, List[int]] = {}
    for institution in institutions:
        institutions_by_type.setdefault(institution.type, []).append(institution.id)

    for institution in institutions:
        metric = metrics[institution.id]
        peers = institutions_by_type[institution.type]
        type_nri = [metrics[i]["nri_share"] for i in peers]
        type_fn = [metrics[i]["fn_share"] for i in peers]
        type_oci = [metrics[i]["oci_share"] for i in peers]
        z_nri = _zscore(metric["nri_share"], type_nri)
        z_fn = _zscore(metric["fn_share"], type_fn)
        z_oci = _zscore(metric["oci_share"], type_oci)
        if (
            metric["nri_share"] > nri_threshold
            or metric["fn_share"] > nri_threshold
            or metric["oci_share"] > nri_threshold
            or max(abs(z_nri), abs(z_fn), abs(z_oci)) > 2
        ):
            score = max(abs(z_nri), abs(z_fn), abs(z_oci), metric["nri_share"], metric["fn_share"], metric["oci_share"])
            alerts.append(
                _make_alert(
                    session,
                    institution.id,
                    "A3",
                    score,
                    "NRI/FN/OCI share is above policy or unusually high versus peer institutions. Recommended action: review quota classifications and supporting records.",
                )
            )

    # A4: same DOB cluster in a program
    programs = session.exec(select(Program)).all()
    for program in programs:
        dob_counts: Dict[str, int] = {}
        students = session.exec(
            select(Student).where(Student.program_id == program.id, Student.status == "ACTIVE")
        ).all()
        for student in students:
            dob = student.dob
            if dob:
                dob_counts[dob] = dob_counts.get(dob, 0) + 1

        cluster_size = max(dob_counts.values(), default=0)
        if cluster_size >= 8:
            alerts.append(
                _make_alert(
                    session,
                    program.institution_id,
                    "A4",
                    float(cluster_size),
                    f"Program '{program.name}' has a cluster of {cluster_size} students sharing the same date of birth.",
                )
            )

    # A5: Isolation Forest on institutional features
    feature_rows: List[List[float]] = []
    feature_index: List[int] = []
    for institution in institutions:
        metric = metrics[institution.id]
        feature_rows.append(
            [
                metric["fill_ratio"],
                metric["nri_share"],
                metric["fn_share"],
                metric["yoy_growth"],
                0.0 if not institution.id else (sum(1 for flag in session.exec(select(ValidationFlag).where(ValidationFlag.institution_id == institution.id, ValidationFlag.status == "OPEN")).all()) / max(1, sum(1 for _ in session.exec(select(Student).where(Student.institution_id == institution.id, Student.status == "ACTIVE")).all()))),
            ]
        )
        feature_index.append(institution.id)

    if len(feature_rows) >= 2:
        model = IsolationForest(contamination=0.2, random_state=42)
        prediction = model.fit_predict(feature_rows)
        for institution_id, flag in zip(feature_index, prediction):
            if flag == -1:
                alerts.append(
                    _make_alert(
                        session,
                        institution_id,
                        "A5",
                        1.0,
                        "The institution's combined pattern is a statistical outlier across intake, growth, FN/NRI risk and open flags.",
                    )
                )

    session.commit()
    return alerts


def compliance_score(institution_id: int, session: Session) -> int:
    """Return an integer compliance score from 0 to 100 for an institution."""
    score = 100

    flags = session.exec(
        select(ValidationFlag).where(
            ValidationFlag.institution_id == institution_id,
            ValidationFlag.status == "OPEN",
        )
    ).all()

    penalty = 0.0
    for flag in flags:
        if flag.severity == "HIGH":
            penalty += 5
        elif flag.severity == "MEDIUM":
            penalty += 2
        elif flag.severity == "LOW":
            penalty += 0.5
    penalty = min(penalty, 70)
    score -= penalty

    anomaly_alerts = session.exec(
        select(AnomalyAlert).where(AnomalyAlert.institution_id == institution_id)
    ).all()
    score -= min(len(anomaly_alerts) * 5, 25)

    return max(0, min(100, int(score)))
