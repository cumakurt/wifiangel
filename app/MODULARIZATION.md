# WiFiAngel Modularization Notes

This document summarizes the controller/service split introduced for `app/wifi_angel.py`.

## Current module boundaries

- `app/wifi_angel.py`
  - Orchestrator class (`WiFiAngel`)
  - Delegates scan, menu routing, and heavy-domain entrypoints
- `app/context/runtime_state.py`
  - Shared runtime dependency container (`RuntimeState`)
- `app/controllers/main_menu.py`
  - Main menu flow
- `app/controllers/attack_menu.py`
  - Attack and deauth menu flows
- `app/controllers/tools_menu.py`
  - Tools and adapter settings menu flows
- `app/controllers/app_controller.py`
  - Top-level application run loop
- `app/services/network/scan_service.py`
  - Discovery, packet aggregation, and live scan table updates
- `app/services/network/targeting_service.py`
  - Target selection and channel-hopping helpers
- `app/services/attacks/evil_twin_service.py`
  - Evil Twin attack flow + cleanup/verification
- `app/services/attacks/mitm_service.py`
  - MITM attack flow + runtime helpers
- `app/services/attacks/auto_hack_orchestrator.py`
  - Auto-hack orchestration + HTML report generation
- `app/services/tools/speed_test_service.py`
  - Speed test entrypoint
- `app/services/tools/bluetooth_iot_service.py`
  - Bluetooth/IoT scan entrypoint
- `app/services/tools/hidden_ssid_service.py`
  - Hidden SSID discovery flow
- `app/services/tools/adapter_service.py`
  - Adapter mode/channel/info/MAC helpers
- `app/services/system/network_helpers.py`
  - Interface/uplink/bootstrap networking helpers
- `app/services/system/lifecycle_service.py`
  - Shutdown cleanup lifecycle
- `app/services/system/bootstrap_service.py`
  - Adapter/tool startup initialization

## Design rules

- Keep `WiFiAngel` as orchestrator, not an implementation dumping ground.
- Place domain logic in `app/services/*`.
- Keep menu rendering and option dispatch in `app/controllers/*`.
- Preserve user-visible behavior while refactoring internals.

## Refactor status (current snapshot)

- Previously planned heavy extractions are completed:
  - `_evil_twin_attack_impl` extracted
  - `_mitm_attack_impl` extracted
  - `_speed_test_impl` extracted
  - `_bluetooth_iot_scanner_impl` extracted
- `app/wifi_angel.py` is now an orchestrator-focused class with delegated domain logic.
- `app/wifi_angel.py` line count reduced from monolithic ~4.8k to ~445 lines.

## Verification baseline

- Keep syntax checks green using AST parse-based validation for edited modules.
- Keep lints clean on touched files (`ReadLints`, optional `pyflakes`).
- Preserve CLI/TUI behavior and menu flow while moving internals.
