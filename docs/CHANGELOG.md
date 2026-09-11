# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

---

## [0.5.0] - 2026-09-11

### Added
- added config_flow to allow modification of connection parameters also after setup
- added DigestAuth option in addition to BasicAuth (PR meanwhile released in underlying py2n)
- added support for SSL verification (default), but also possible to disable
- added option to disable creation of control entities (e.g. switches), only create sensor entities instead (don't let Home Assistant control the lock, only update status)
- added UserAuthenticated Event entity for better UI visibility of access events
- add diagnostic Log Subscription Health entity
- add serial number, device name and config entry id to all events to allow to distinguish between events from different devices
- include brand logos (taken from homeassistant brands repository)
- brand assets (logos and icons)
- add unit tests & github actions

### Changed
- required Home Assistant version raised to 2026.2 to avoid handling different config flows etc.
- make HTTPS default
- expanded `config_flow.py` with full validation, error mapping, and options flow
- split log polling logic from `__init__.py` into dedicated `log.py` module
- update switch and sensor entities directly from log subscription for almost real-time updates, only use polling for verification and after start-up
- increase polling interval from 10s to 30s
- change to `iot_class: local_push`
- extend logging (mostly debug level)
- update & extend README, add `docs/events.md` with example payloads for supported log events
- migrated project structure from `requirements.txt` to `pyproject.toml`

### Security
- Use Home Assistant's `async_get_clientsession` instead of custom `aiohttp.ClientSession`
- Sanitized connection credentials in logger output
- Added input validation for manual API service (endpoint path traversal, method allowlist, timeout bounds)

---

## [0.4.1] - 2025-03-20

### Fixed
- Fix config flow
