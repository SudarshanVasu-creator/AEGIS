"""Severity count labels for scan findings."""

from __future__ import annotations

from collections import Counter

from PySide6.QtWidgets import QHBoxLayout, QLabel, QWidget

from aegis.models import Finding, Severity


class SeverityChips(QWidget):
    """Show accessible text counters for every supported severity."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._labels: dict[Severity, QLabel] = {}

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        for severity in Severity:
            label = QLabel()
            label.setObjectName("severityChip")
            label.setProperty("severity", severity.value)
            label.setAccessibleName(f"{severity.value} findings")
            label.style().unpolish(label)
            label.style().polish(label)
            self._labels[severity] = label
            layout.addWidget(label)
        layout.addStretch()
        self.update_counts([])

    def update_counts(self, findings: list[Finding]) -> None:
        """Recalculate all counts directly from the supplied findings."""
        counts = Counter(finding.severity for finding in findings)
        for severity, label in self._labels.items():
            count = counts[severity]
            label.setText(f"{severity.value}  {count}")
            label.setAccessibleDescription(
                f"{count} {severity.value.lower()} findings"
            )

    def counts(self) -> dict[Severity, int]:
        """Return the counts currently displayed by the chips."""
        return {
            severity: int(label.text().rsplit(" ", maxsplit=1)[-1])
            for severity, label in self._labels.items()
        }
