## WiFi OTA Firmware

 - Fits into 640KB for all esp32 targets
 - Compatible with `espota.py` from arduino-esp32

### Usage

Build and write OTA binary to the `ota_1` partition (take its address from `partition-table.csv`):
```
pio run [-e <target>]
esptool.py --port <...> write_flash 0x260000 .pio/build/<target>/firmware.bin
```
After rebooting the device into OTA firmware (the main firmware has to have some way of doing that), upload a new main firmware binary over network:
```
espota.py --ip <device-ip-address> --file <new-main-firmware.bin>
```
Uploading a filesystem image to a `spiffs` partition:
```
espota.py --ip <device-ip-address> --file <littlefs.bin> --spiffs
```

### Details

 - To be able to connect to a WiFi access point, OTA firmware expects to find `ssid` and `psk` string fields in the NVRAM storage under `ota-wifi` namespace.
 - After successful flashing, a boolean field `updated` is raised, so that the main firmware can handle the "first boot after update" scenario.
 - OTA firmware waits for an upload only for some limited time and then reboots back to main on timeout.
