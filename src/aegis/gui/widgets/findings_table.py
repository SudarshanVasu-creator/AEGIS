"""Table view for scan findings."""

from __future__ import annotations

from collections import Counter

from PySide6.QtCore import QModelIndex, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QComboBox,
    QHeaderView,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from aegis.gui.styles import SEVERITY_COLORS
from aegis.models import Finding, Severity


class FindingsTable(QWidget):
    """Display findings in backend order and emit the selected finding."""

    finding_selected = Signal(object)
    selection_cleared = Signal()

    _HEADERS = ("Severity", "Finding", "Rule", "File", "Line")
    _SEVERITY_ORDER = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._findings: list[Finding] = []
        self._active_filter: Severity | None = None

        self.table = QTableView(self)
        self.table.setObjectName("findingsTable")
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(False)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(30)
        self.table.setAlternatingRowColors(True)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        self.model = QStandardItemModel(0, len(self._HEADERS), self.table)
        self.model.setHorizontalHeaderLabels(list(self._HEADERS))
        self.table.setModel(self.model)
        self.table.setColumnWidth(2, 86)
        self.table.setColumnWidth(3, 155)
        self.table.setColumnWidth(4, 46)
        self.table.selectionModel().currentRowChanged.connect(
            self._on_current_row_changed
        )
        self.table.selectionModel().selectionChanged.connect(
            self._on_selection_changed
        )

        filters = QHBoxLayout()
        filters.setContentsMargins(0, 0, 0, 0)
        filters.setSpacing(5)
        self.filter_group = QButtonGroup(self)
        self.filter_group.setExclusive(True)
        self.filter_buttons: dict[Severity | None, QPushButton] = {}
        all_button = self._filter_button("All", None)
        all_button.setChecked(True)
        filters.addWidget(all_button)
        for severity in Severity:
            button = self._filter_button(severity.value.title(), severity)
            filters.addWidget(button)
        filters.addStretch()

        self.search_edit = QLineEdit(self)
        self.search_edit.setObjectName("findingSearch")
        self.search_edit.setPlaceholderText("Search file, title or rule ID")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.setMaximumWidth(240)
        self.search_edit.textChanged.connect(self._refresh)
        filters.addWidget(self.search_edit)

        self.sort_combo = QComboBox(self)
        self.sort_combo.setObjectName("findingSort")
        self.sort_combo.addItems(["Severity", "File", "Line"])
        self.sort_combo.setMaximumWidth(130)
        self.sort_combo.currentTextChanged.connect(self._refresh)
        filters.addWidget(self.sort_combo)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        layout.addLayout(filters)
        layout.addWidget(self.table)

    def load_findings(self, findings: list[Finding]) -> None:
        """Replace findings and refresh filters, sorting, and displayed counts."""
        self._findings = list(findings)
        counts = Counter(finding.severity for finding in findings)
        for severity, button in self.filter_buttons.items():
            if severity is None:
                button.setText(f"All {len(findings)}")
            else:
                button.setText(f"{severity.value.title()} {counts[severity]}")
        self._refresh()

    def clear(self) -> None:
        """Remove all findings and selection."""
        self._findings = []
        self.load_findings([])

    def _filter_button(
        self,
        label: str,
        severity: Severity | None,
    ) -> QPushButton:
        button = QPushButton(label, self)
        button.setObjectName("severityFilter")
        button.setCheckable(True)
        if severity is not None:
            button.setProperty("severity", severity.value)
        self.filter_group.addButton(button)
        self.filter_buttons[severity] = button
        button.clicked.connect(lambda _checked, selected=severity: self._set_filter(selected))
        return button

    def _set_filter(self, severity: Severity | None) -> None:
        self._active_filter = severity
        self._refresh()

    def _refresh(self, _value: str = "") -> None:
        """Rebuild visible rows while keeping each row bound to its finding."""
        query = self.search_edit.text().strip().casefold()
        findings = [
            finding
            for finding in self._findings
            if (self._active_filter is None or finding.severity is self._active_filter)
            and (
                not query
                or query in finding.file.casefold()
                or query in finding.title.casefold()
                or query in finding.rule_id.casefold()
            )
        ]
        sort_by = self.sort_combo.currentText()
        if sort_by == "File":
            findings.sort(key=lambda finding: (finding.file.casefold(), finding.line or 0))
        elif sort_by == "Line":
            findings.sort(key=lambda finding: (finding.line is None, finding.line or 0))
        else:
            findings.sort(
                key=lambda finding: (
                    self._SEVERITY_ORDER[finding.severity],
                    finding.file.casefold(),
                    finding.line or 0,
                )
            )

        self.table.clearSelection()
        self.table.setCurrentIndex(QModelIndex())
        self.model.removeRows(0, self.model.rowCount())
        for finding in findings:
            values = (
                finding.severity.value,
                finding.title,
                finding.rule_id,
                finding.file,
                str(finding.line) if finding.line is not None else "—",
            )
            items = [QStandardItem(value) for value in values]
            for item in items:
                item.setTextAlignment(
                    Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft
                )
            background, foreground = SEVERITY_COLORS[finding.severity.value]
            items[0].setBackground(QBrush(QColor(background)))
            items[0].setForeground(QBrush(QColor(foreground)))
            items[0].setData(finding, Qt.ItemDataRole.UserRole)
            self.model.appendRow(items)
        self.selection_cleared.emit()

    def _on_current_row_changed(self, current, _previous) -> None:
        if not current.isValid():
            return
        item = self.model.item(current.row(), 0)
        if item is not None:
            finding = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(finding, Finding):
                self.finding_selected.emit(finding)

    def _on_selection_changed(self, selected, _deselected) -> None:
        if selected.isEmpty():
            self.selection_cleared.emit()
