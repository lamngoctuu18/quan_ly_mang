"""Qt Model/View implementation for high-performance device table rendering, sorting, filtering, and multi-select."""

from __future__ import annotations

import ipaddress
from typing import Any
from uuid import UUID

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
    QSortFilterProxyModel,
    Qt,
)

from lan_manager.domain.models.entities import Device
from lan_manager.ui.components.status_badge import colors_for_table_status

_EMPTY_INDEX = QModelIndex()


class DeviceTableModel(QAbstractTableModel):
    """
    Qt TableModel for displaying large lists of LAN devices with checkbox selection.
    Columns:
    0: [x] Select
    1: IP Address
    2: Hostname
    3: MAC Address
    4: Loại thiết bị (Device Type)
    5: Nhà sản xuất / Model
    6: Trạng thái (Status)
    7: Lần kiểm tra gần nhất (Last Seen)
    8: Hành động (Xem chi tiết)
    """

    COL_SELECT = 0
    COL_IP = 1
    COL_HOSTNAME = 2
    COL_MAC = 3
    COL_TYPE = 4
    COL_VENDOR = 5
    COL_STATUS = 6
    COL_LAST_SEEN = 7
    COL_ACTION = 8

    HEADERS = (
        "Chọn",
        "Địa chỉ IP",
        "Hostname",
        "Địa chỉ MAC",
        "Loại thiết bị",
        "Nhà sản xuất / Model",
        "Trạng thái",
        "Kiểm tra gần nhất",
        "Chi tiết",
    )

    USER_ROLE_DEVICE = Qt.ItemDataRole.UserRole + 1
    USER_ROLE_IP_INT = Qt.ItemDataRole.UserRole + 2

    def __init__(self, devices: list[Device] | None = None) -> None:
        super().__init__()
        self._devices: list[Device] = list(devices or [])
        self._checked_ids: set[UUID] = set()

    def set_devices(self, devices: list[Device]) -> None:
        self.beginResetModel()
        self._devices = list(devices)
        valid_ids = {d.id for d in self._devices}
        self._checked_ids.intersection_update(valid_ids)
        self.endResetModel()

    def get_device_at(self, row: int) -> Device | None:
        if 0 <= row < len(self._devices):
            return self._devices[row]
        return None

    def get_selected_devices(self) -> list[Device]:
        return [d for d in self._devices if d.id in self._checked_ids]

    def select_all(self, checked: bool = True) -> None:
        if not self._devices:
            return
        if checked:
            self._checked_ids = {d.id for d in self._devices}
        else:
            self._checked_ids.clear()
        top_left = self.index(0, self.COL_SELECT)
        bottom_right = self.index(len(self._devices) - 1, self.COL_SELECT)
        self.dataChanged.emit(top_left, bottom_right, [Qt.ItemDataRole.CheckStateRole])

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = _EMPTY_INDEX) -> int:
        if parent.isValid():
            return 0
        return len(self._devices)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = _EMPTY_INDEX) -> int:
        if parent.isValid():
            return 0
        return len(self.HEADERS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            if 0 <= section < len(self.HEADERS):
                return self.HEADERS[section]
        return None

    def flags(self, index: QModelIndex | QPersistentModelIndex) -> Qt.ItemFlag:
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        base_flags = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if index.column() == self.COL_SELECT:
            return base_flags | Qt.ItemFlag.ItemIsUserCheckable
        return base_flags

    def data(
        self,
        index: QModelIndex | QPersistentModelIndex,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if not index.isValid() or not (0 <= index.row() < len(self._devices)):
            return None

        dev = self._devices[index.row()]
        col = index.column()

        if role == self.USER_ROLE_DEVICE:
            return dev

        if role == self.USER_ROLE_IP_INT:
            try:
                return int(ipaddress.ip_address(dev.ip_address))
            except ValueError:
                return 0

        if role == Qt.ItemDataRole.CheckStateRole and col == self.COL_SELECT:
            return Qt.CheckState.Checked if dev.id in self._checked_ids else Qt.CheckState.Unchecked

        if role == Qt.ItemDataRole.DisplayRole:
            if col == self.COL_IP:
                return dev.ip_address
            if col == self.COL_HOSTNAME:
                return dev.hostname or "—"
            if col == self.COL_MAC:
                return dev.mac_address or "—"
            if col == self.COL_TYPE:
                return dev.device_type.label_vi
            if col == self.COL_VENDOR:
                parts = [p for p in (dev.manufacturer, dev.model) if p]
                return " / ".join(parts) if parts else "—"
            if col == self.COL_STATUS:
                return dev.status.label_vi
            if col == self.COL_LAST_SEEN:
                if dev.last_seen_at:
                    return dev.last_seen_at.astimezone().strftime("%Y-%m-%d %H:%M:%S")
                return "Chưa kiểm tra"
            if col == self.COL_ACTION:
                return "Xem chi tiết"

        if role == Qt.ItemDataRole.BackgroundRole and col == self.COL_STATUS:
            bg, _ = colors_for_table_status(dev.status.value)
            return bg

        if role == Qt.ItemDataRole.ForegroundRole:
            if col == self.COL_STATUS:
                _, fg = colors_for_table_status(dev.status.value)
                return fg
            if col == self.COL_ACTION:
                _, fg = colors_for_table_status("ONLINE")
                return fg

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (self.COL_SELECT, self.COL_STATUS, self.COL_ACTION):
                return Qt.AlignmentFlag.AlignCenter
            return Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft

        return None

    def setData(
        self,
        index: QModelIndex | QPersistentModelIndex,
        value: Any,
        role: int = Qt.ItemDataRole.EditRole,
    ) -> bool:
        if not index.isValid() or index.column() != self.COL_SELECT:
            return False
        if role == Qt.ItemDataRole.CheckStateRole:
            dev = self._devices[index.row()]
            state = Qt.CheckState(value)
            if state == Qt.CheckState.Checked:
                self._checked_ids.add(dev.id)
            else:
                self._checked_ids.discard(dev.id)
            self.dataChanged.emit(index, index, [Qt.ItemDataRole.CheckStateRole])
            return True
        return False


class DeviceSortFilterProxyModel(QSortFilterProxyModel):
    """Proxy model providing numerical IP sorting and instant client-side text/type/status filtering."""

    def __init__(self) -> None:
        super().__init__()
        self._search_text = ""
        self._type_filter = ""
        self._status_filter = ""
        self.setDynamicSortFilter(True)

    def set_filters(
        self,
        search_text: str = "",
        type_filter: str = "",
        status_filter: str = "",
    ) -> None:
        self._search_text = search_text.strip().lower()
        self._type_filter = type_filter.strip()
        self._status_filter = status_filter.strip()
        self.invalidateFilter()

    def filterAcceptsRow(
        self, source_row: int, source_parent: QModelIndex | QPersistentModelIndex
    ) -> bool:
        model = self.sourceModel()
        if not isinstance(model, DeviceTableModel):
            return True
        idx = model.index(source_row, 0, source_parent)
        dev: Device | None = model.data(idx, DeviceTableModel.USER_ROLE_DEVICE)
        if dev is None:
            return False

        if self._type_filter and dev.device_type.value != self._type_filter:
            return False
        if self._status_filter and dev.status.value != self._status_filter:
            return False
        if self._search_text:
            haystack = " ".join(
                filter(
                    None,
                    [
                        dev.ip_address,
                        dev.hostname,
                        dev.mac_address,
                        dev.manufacturer,
                        dev.model,
                        dev.location,
                    ],
                )
            ).lower()
            if self._search_text not in haystack:
                return False
        return True

    def lessThan(
        self,
        source_left: QModelIndex | QPersistentModelIndex,
        source_right: QModelIndex | QPersistentModelIndex,
    ) -> bool:
        if source_left.column() == DeviceTableModel.COL_IP:
            left_ip = self.sourceModel().data(source_left, DeviceTableModel.USER_ROLE_IP_INT) or 0
            right_ip = self.sourceModel().data(source_right, DeviceTableModel.USER_ROLE_IP_INT) or 0
            return int(left_ip) < int(right_ip)
        return super().lessThan(source_left, source_right)
