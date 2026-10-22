"""Safe, readable detail view for a selected finding."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFormLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from aegis.models import Finding


class FindingDetail(QWidget):
    """Show finding metadata and only its backend-redacted evidence."""

    _FIELD_LABELS = {
        "severity": "Severity",
        "file": "File",
        "line": "Line",
        "rule_id": "Rule ID",
    }

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("findingDetail")

        content = QWidget()
        content.setObjectName("detailContent")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(12, 12, 12, 12)
        content_layout.setSpacing(9)

        self.title_label = QLabel("Select a finding to view its details.")
        self.title_label.setObjectName("pageTitle")
        self.title_label.setWordWrap(True)
        self.title_label.setTextFormat(Qt.TextFormat.PlainText)
        content_layout.addWidget(self.title_label)

        metadata = QFormLayout()
        metadata.setHorizontalSpacing(12)
        metadata.setVerticalSpacing(6)
        self.fields: dict[str, QLabel] = {}
        for key, label_text in self._FIELD_LABELS.items():
            label = QLabel(label_text)
            label.setObjectName("detailFieldLabel")
            value = self._value_label()
            self.fields[key] = value
            metadata.addRow(label, value)
        content_layout.addLayout(metadata)

        self.description_label = self._section_value("Description")
        content_layout.addWidget(self.description_label)

        self.evidence_label = self._section_value("Redacted evidence")
        self.evidence_label.setObjectName("redactedEvidence")
        self.evidence_label.setFont(QFont("Consolas", 9))
        content_layout.addWidget(self.evidence_label)

        self.remediation_label = self._section_value("Remediation")
        content_layout.addWidget(self.remediation_label)
        content_layout.addStretch()

        scroll = QScrollArea(self)
        scroll.setObjectName("detailScrollArea")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(content)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(scroll)
        self.clear()

    def _value_label(self) -> QLabel:
        label = QLabel()
        label.setWordWrap(True)
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        label.setObjectName("detailValue")
        return label

    def _section_value(self, heading: str) -> QLabel:
        label = self._value_label()
        label.setProperty("sectionHeading", heading)
        return label

    def load_finding(self, finding: Finding) -> None:
        """Render the selected finding without accessing raw evidence."""
        self.title_label.setText(self._display_value(finding.title))
        self.fields["severity"].setText(self._display_value(finding.severity.value))
        self.fields["file"].setText(self._display_value(finding.file))
        self.fields["line"].setText(
            str(finding.line) if finding.line is not None else "Not available"
        )
        self.fields["rule_id"].setText(self._display_value(finding.rule_id))
        self.description_label.setText(
            "Description\n" + self._display_value(finding.description)
        )
        self.evidence_label.setText(
            "Redacted evidence\n"
            + self._display_value(finding.redacted, "No redacted evidence available.")
        )
        self.remediation_label.setText(
            "Remediation\n"
            + self._display_value(
                finding.remediation, "No remediation guidance available."
            )
        )

    def clear(self) -> None:
        """Clear any previously selected finding details."""
        self.title_label.setText("Select a finding to view its details.")
        for value in self.fields.values():
            value.clear()
        self.description_label.setText("Description\nNot provided.")
        self.evidence_label.setText(
            "Redacted evidence\nNo redacted evidence available."
        )
        self.remediation_label.setText(
            "Remediation\nNo remediation guidance available."
        )

    @staticmethod
    def _display_value(value: str, fallback: str = "Not provided.") -> str:
        return value if value else fallback
