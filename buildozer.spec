[app]
title = Safe Net Probe
package.name = safenetprobe
package.domain = org.example
source.dir = .
source.include_exts = py,kv,txt,md,mmdb,html,csv,json
version = 0.1.0
orientation = portrait
fullscreen = 0
requirements = python3, kivy, pyjnius, plyer, androidstorage4kivy, httpx, httpcore, h11, h2, hpack, hyperframe, anyio, sniffio, idna, certifi, dnspython

include_patterns = hosts_master.txt, extra_hosts.txt, GeoLite2-ASN.mmdb, GeoLite2-Country.mmdb, fileprovider_paths.xml

# icon.filename = ./icon.png
# presplash.filename = ./presplash.png

android.permissions = INTERNET, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE, ACCESS_FINE_LOCATION, ACCESS_COARSE_LOCATION, READ_PHONE_STATE, READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE, NEARBY_WIFI_DEVICES

android.enable_androidx = True

# API/NDK
android.api = 33
android.minapi = 24
android.ndk = 25b

android.manifest_xml = ./android_manifest.xml
android.file_provider_paths = ./fileprovider_paths.xml


[buildozer]
log_level = 2
warn_on_root = 0
