"""Qustodio sensor platform."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorDeviceClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import ATTRIBUTION, DOMAIN, ICON_IN_TIME, ICON_NO_TIME, MANUFACTURER

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up Qustodio sensor based on a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]
    
    profiles = entry.data.get("profiles", {})
    
    entities = []
    for profile_id, profile_data in profiles.items():
        entities.append(QustodioSensor(coordinator, profile_data))
    
    async_add_entities(entities)


class QustodioSensor(CoordinatorEntity, SensorEntity):
    """Qustodio sensor class."""

    def __init__(self, coordinator: Any, profile_data: dict[str, Any]) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._profile_id = profile_data["id"]
        self._profile_name = profile_data["name"]
        
        self._attr_name = f"Qustodio {self._profile_name}"
        self._attr_unique_id = f"{DOMAIN}_{self._profile_id}"
        self._attr_attribution = ATTRIBUTION
        self._attr_device_class = SensorDeviceClass.DURATION
        self._attr_native_unit_of_measurement = UnitOfTime.MINUTES
        self._attr_suggested_display_precision = 1
        
        self._attr_device_info = {
            "identifiers": {(DOMAIN, self._profile_id)},
            "name": self._profile_name,
            "manufacturer": MANUFACTURER,
        }

    @property
    def native_value(self) -> float | None:
        """Return the state of the sensor."""
        if self.coordinator.data and self._profile_id in self.coordinator.data:
            return self.coordinator.data[self._profile_id].get("time")
        return None

    @property
    def icon(self) -> str:
        """Return the icon of the sensor."""
        if self.coordinator.data and self._profile_id in self.coordinator.data:
            data = self.coordinator.data[self._profile_id]
            time_used = data.get("time", 0)
            quota = data.get("quota", 0)
            
            if time_used < quota:
                return ICON_IN_TIME
        return ICON_NO_TIME

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Return the state attributes."""
        if self.coordinator.data and self._profile_id in self.coordinator.data:
            data = self.coordinator.data[self._profile_id]
            return {
                "attribution": ATTRIBUTION,
                "time": data.get("time"),
                "current_device": data.get("current_device"),
                "is_online": data.get("is_online"),
                "quota": data.get("quota"),
                "unauthorized_remove": data.get("unauthorized_remove"),
                "device_tampered": data.get("device_tampered"),
            }
        return None

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        return (
            self.coordinator.last_update_success
            and self.coordinator.data is not None
            and self._profile_id in self.coordinator.data
        )