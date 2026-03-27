# Example Events

The integration subscribes to the device's event log and replicates the events onto Home Assistant's event bus. Subscribe to `helios2n_event` to see which events are fired. Each event payload contains the original log event from the API.


## WavekeyActivated

```yaml
event_type: helios2n_event
data:
  id: 58
  hash: a3f8c2d9b5e7a491
  tzShift: 60
  utcTime: 1712345678
  upTime: 456789
  event: WaveKeyActivated
  params:
    type: touch
  device_serial: 12-3456-7890
  device_name: StorageRoom
  config_entry_id: ABC123DEF456GHI789JKL012MNO345
origin: LOCAL
time_fired: "2025-04-05T14:23:45.123456+00:00"
context:
  id: XYZ789UVW456ABC123DEF567GHI890
  parent_id: null
  user_id: null
```

## KeyPressed

```yaml
event_type: helios2n_event
data:
  id: 59
  hash: 9c2d4e6f8a1b5c7d
  tzShift: 60
  utcTime: 1712345678
  upTime: 456789
  event: KeyPressed
  params:
    key: A
  device_serial: 12-3456-7890
  device_name: StorageRoom
  config_entry_id: ABC123DEF456GHI789JKL012MNO345
origin: LOCAL
time_fired: "2025-04-05T14:23:45.234567+00:00"
context:
  id: PQR456STU789VWX012YZA345BCD678
  parent_id: null
  user_id: null
```

## MobKeyEntered

```yaml
event_type: helios2n_event
data:
  id: 60
  hash: 5e8a2c1f9d3b7a4e
  tzShift: 60
  utcTime: 1712345678
  upTime: 456789
  event: MobKeyEntered
  params:
    ap: 0
    session: 1
    direction: in
    action: 0
    authid: 8f6e5d4c3b2a1987
    uuid: 11111111-2222-3333-4444-555555555555
    valid: true
  device_serial: 12-3456-7890
  device_name: StorageRoom
  config_entry_id: ABC123DEF456GHI789JKL012MNO345
origin: LOCAL
time_fired: "2025-04-05T14:23:45.345678+00:00"
context:
  id: EFG123HIJ456KLM789NOP012QRS345
  parent_id: null
  user_id: null
```

## User Authenticated

```yaml
event_type: helios2n_event
data:
  id: 61
  hash: 1a7b9c3d5e6f8a2b
  tzShift: 60
  utcTime: 1712345678
  upTime: 456789
  event: UserAuthenticated
  params:
    ap: 0
    session: 1
    name: Smith John 123456
    uuid: 11111111-2222-3333-4444-555555555555
  device_serial: 12-3456-7890
  device_name: StorageRoom
  config_entry_id: ABC123DEF456GHI789JKL012MNO345
origin: LOCAL
time_fired: "2025-04-05T14:23:45.456789+00:00"
context:
  id: TUV345WXY678ZAB901CDE234FGH567
  parent_id: null
  user_id: null
```

## SwitchStateChanged

```yaml
event_type: helios2n_event
data:
  id: 62
  hash: 7c2d9e4f5a8b6c3d
  tzShift: 60
  utcTime: 1712345678
  upTime: 456789
  event: SwitchStateChanged
  params:
    ap: 0
    session: 1
    switch: 1
    state: true
    originator: ap
  device_serial: 12-3456-7890
  device_name: StorageRoom
  config_entry_id: ABC123DEF456GHI789JKL012MNO345
origin: LOCAL
time_fired: "2025-04-05T14:23:45.567890+00:00"
context:
  id: IJK567LMN901OPQ234RST678UVW901
  parent_id: null
  user_id: null
```

## OutputChanged

```yaml
event_type: helios2n_event
data:
  id: 63
  hash: 2e5f8a7b3c9d1a4f
  tzShift: 60
  utcTime: 1712345678
  upTime: 456789
  event: OutputChanged
  params:
    port: relay1
    state: true
  device_serial: 12-3456-7890
  device_name: StorageRoom
  config_entry_id: ABC123DEF456GHI789JKL012MNO345
origin: LOCAL
time_fired: "2025-04-05T14:23:45.678901+00:00"
context:
  id: WXY901ZAB234CDE567FGH890IJK123
  parent_id: null
  user_id: null
```