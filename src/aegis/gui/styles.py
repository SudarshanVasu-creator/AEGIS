"""Centralized Qt stylesheet and design tokens for the AEGIS GUI."""

BG_CANVAS = "#101315"
BG_CARD = "#15191c"
BG_ELEVATED = "#1b2024"
TEXT_PRIMARY = "#e7edf0"
TEXT_SECONDARY = "#929da3"
BORDER = "#2a3237"
ACCENT = "#55c6d7"

FONT_FAMILY = "Segoe UI"
BASE_FONT_SIZE = 9
LABEL_FONT_SIZE = 8

WINDOW_PADDING = 14
SECTION_GAP = 10
CARD_PADDING = 12

SEVERITY_COLORS = {
    "CRITICAL": ("#301b20", "#ff777c"),
    "HIGH": ("#30251b", "#ffb45f"),
    "MEDIUM": ("#302d1b", "#e7d56d"),
    "LOW": ("#192d35", "#70c8dc"),
    "INFO": ("#24282b", "#aab4b9"),
}


def build_stylesheet() -> str:
    """Return the application-wide Qt stylesheet."""
    severity_rules = "\n".join(
        f"""
        QLabel#severityChip[severity="{severity}"] {{
            background-color: {background};
            color: {foreground};
        }}
        QPushButton#severityFilter[severity="{severity}"] {{
            color: {foreground};
        }}
        QPushButton#severityFilter[severity="{severity}"]:checked {{
            background-color: {background};
            border-color: {foreground};
        }}
        """
        for severity, (background, foreground) in SEVERITY_COLORS.items()
    )
    return f"""
        QMainWindow,
        QWidget#appSurface {{
            background-color: {BG_CANVAS};
        }}

        QWidget {{
            color: {TEXT_PRIMARY};
            font-family: "{FONT_FAMILY}";
            font-size: {BASE_FONT_SIZE}pt;
        }}

        QFrame#headerBar,
        QFrame#placeholderCard,
        QFrame#pathCard {{
            background-color: {BG_CARD};
            border: 1px solid {BORDER};
            border-radius: 5px;
        }}

        QLabel#wordmark {{
            color: {TEXT_PRIMARY};
            font-size: 15pt;
            font-weight: 700;
        }}

        QLabel#brandSubtitle,
        QLabel#secondaryText,
        QLabel#statusMessage,
        QLabel#pathHint {{
            color: {TEXT_SECONDARY};
            font-size: {LABEL_FONT_SIZE}pt;
        }}

        QLabel#privacyLabel {{
            color: {ACCENT};
            font-size: {LABEL_FONT_SIZE}pt;
            font-weight: 600;
        }}

        QLabel#sectionLabel {{
            color: {TEXT_SECONDARY};
            font-size: {LABEL_FONT_SIZE}pt;
            font-weight: 600;
        }}

        QLabel#pageTitle {{
            color: {TEXT_PRIMARY};
            font-size: 12pt;
            font-weight: 600;
        }}

        QLabel#findingCount {{
            color: {ACCENT};
            font-size: 10pt;
            font-weight: 700;
        }}

        QLabel#inlineError {{
            color: #ff8585;
            font-size: {LABEL_FONT_SIZE}pt;
        }}

        QLabel#reportStatus {{
            color: {ACCENT};
            font-size: {LABEL_FONT_SIZE}pt;
        }}

        QFrame#resultBanner {{
            border: 1px solid {BORDER};
            border-radius: 4px;
        }}

        QFrame#resultBanner[bannerStyle="partial"] {{
            background-color: #2d291b;
            color: #f0d77b;
            border-color: #62552b;
        }}

        QFrame#resultBanner[bannerStyle="failed"] {{
            background-color: #2a171a;
            color: #ff8d91;
            border-color: #62343a;
        }}

        QFrame#resultBanner[bannerStyle="info"] {{
            background-color: #17272a;
            color: #8adbe5;
            border-color: #28515a;
        }}

        QLabel#bannerMessage {{
            background-color: transparent;
        }}

        QLabel#severityChip {{
            border: 1px solid {BORDER};
            border-radius: 4px;
            padding: 4px 7px;
            font-size: {LABEL_FONT_SIZE}pt;
            font-weight: 600;
        }}

        QTableView#findingsTable {{
            background-color: {BG_CARD};
            alternate-background-color: #181d20;
            color: {TEXT_PRIMARY};
            border: 1px solid {BORDER};
            border-radius: 4px;
            gridline-color: transparent;
            outline: 0;
            selection-background-color: #1c353a;
            selection-color: {TEXT_PRIMARY};
        }}

        QHeaderView {{
            background-color: {BG_CARD};
        }}

        QTableCornerButton::section {{
            background-color: {BG_CARD};
            border: none;
        }}

        QTableView#findingsTable::item {{
            padding: 4px 6px;
            border-bottom: 1px solid #22292d;
        }}

        QTableView#findingsTable::item:selected {{
            background-color: #1c353a;
            color: {TEXT_PRIMARY};
        }}

        QHeaderView::section {{
            background-color: {BG_CARD};
            color: {TEXT_SECONDARY};
            border: none;
            border-bottom: 1px solid {BORDER};
            padding: 6px;
            font-size: {LABEL_FONT_SIZE}pt;
            font-weight: 600;
        }}

        QFrame#findingDetail,
        QScrollArea#detailScrollArea,
        QWidget#detailContent {{
            background-color: {BG_CARD};
        }}

        QLabel#detailFieldLabel {{
            color: {TEXT_SECONDARY};
            font-size: {LABEL_FONT_SIZE}pt;
            font-weight: 600;
        }}

        QLabel#detailValue {{
            background-color: transparent;
        }}

        QLabel#redactedEvidence {{
            background-color: #101416;
            color: #b9d7db;
            border: 1px solid {BORDER};
            border-radius: 3px;
            padding: 7px;
        }}

        QLineEdit,
        QComboBox {{
            background-color: #101416;
            color: {TEXT_PRIMARY};
            border: 1px solid {BORDER};
            border-radius: 3px;
            padding: 6px 8px;
            selection-background-color: #1c5962;
        }}

        QLineEdit:focus,
        QComboBox:focus,
        QTableView:focus,
        QPushButton:focus {{
            border: 1px solid {ACCENT};
        }}

        QComboBox QAbstractItemView {{
            background-color: {BG_ELEVATED};
            color: {TEXT_PRIMARY};
            selection-background-color: #1c5962;
        }}

        QPushButton {{
            background-color: {BG_ELEVATED};
            color: {TEXT_PRIMARY};
            border: 1px solid {BORDER};
            border-radius: 3px;
            padding: 6px 10px;
            font-weight: 600;
        }}

        QPushButton:hover {{
            border-color: #53636a;
            background-color: #22292d;
        }}

        QPushButton:checked,
        QPushButton#scanButton {{
            background-color: #17434a;
            color: #a6edf4;
            border: 1px solid #2d7883;
        }}

        QPushButton#scanButton {{
            padding: 8px 14px;
        }}

        QPushButton:disabled {{
            color: #6d787d;
            background-color: #1a1e21;
            border-color: #272d30;
        }}

        QPushButton#severityFilter {{
            padding: 4px 7px;
            font-size: {LABEL_FONT_SIZE}pt;
        }}

        QSplitter::handle {{
            background-color: {BORDER};
            width: 1px;
        }}

        QScrollBar:vertical {{
            background-color: #101416;
            width: 8px;
            margin: 0;
        }}

        QScrollBar:horizontal {{
            background-color: #101416;
            height: 8px;
            margin: 0;
        }}

        QScrollBar::handle:vertical,
        QScrollBar::handle:horizontal {{
            background-color: #465158;
            border-radius: 3px;
            min-height: 24px;
            min-width: 24px;
        }}

        QScrollBar::add-line,
        QScrollBar::sub-line {{
            width: 0;
            height: 0;
        }}

        QProgressBar {{
            background-color: #20272b;
            border: none;
            border-radius: 2px;
            min-height: 4px;
            max-height: 4px;
        }}

        QProgressBar::chunk {{
            background-color: {ACCENT};
            border-radius: 2px;
        }}

        QFrame {{
            color: {TEXT_PRIMARY};
        }}
    """ + severity_rules
