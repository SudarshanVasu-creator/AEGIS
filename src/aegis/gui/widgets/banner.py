"""State banners for partial and failed scan results."""

from __future__ import annotations

import enum

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QWidget


class BannerStyle(enum.Enum):
    """Supported visual variants for a result banner."""

    PARTIAL = "partial"
    FAILED = "failed"
    INFO = "info"


class Banner(QFrame):
    """Compact, accessible banner with explicit state styling."""

    def __init__(
        self,
        style: BannerStyle,
        message: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("resultBanner")

        self.label = QLabel(message, self)
        self.label.setObjectName("bannerMessage")
        self.label.setTextFormat(Qt.TextFormat.PlainText)
        self.label.setWordWrap(True)
        self.label.setAccessibleName(f"{style.name.title()} scan status")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.addWidget(self.label)
        self.set_content(style, message)

    def set_content(self, style: BannerStyle, message: str) -> None:
        """Update the banner variant and message in place."""
        self.setProperty("bannerStyle", style.value)
        self.label.setText(message)
        self.label.setAccessibleName(f"{style.name.title()} scan status")
        self.style().unpolish(self)
        self.style().polish(self)
