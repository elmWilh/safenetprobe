# network_info.py
import socket, sys

def _local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return None

def _android_snapshot():
    from jnius import autoclass, cast
    Context = autoclass('android.content.Context')
    PythonActivity = autoclass('org.kivy.android.PythonActivity')
    activity = PythonActivity.mActivity

    cm = cast('android.net.ConnectivityManager', activity.getSystemService(Context.CONNECTIVITY_SERVICE))
    tm = cast('android.telephony.TelephonyManager', activity.getSystemService(Context.TELEPHONY_SERVICE))
    wifi = cast('android.net.wifi.WifiManager', activity.getApplicationContext().getSystemService(Context.WIFI_SERVICE))

    active = None
    try:
        ni = cm.getActiveNetworkInfo()
        if ni and ni.isConnected():
            active = ni.getTypeName()  # "WIFI" / "MOBILE" / "ETHERNET"
    except Exception:
        pass

    operator = None; plmn = None; gen = None; cell_dbm = None
    try:
        operator = tm.getNetworkOperatorName()
    except Exception:
        pass
    try:
        plmn = tm.getNetworkOperator()  # MCCMNC
    except Exception:
        pass
    try:
        # map TelephonyManager.NETWORK_TYPE_* to human string
        ntype = tm.getDataNetworkType()
        GEN = {
            20: "5G NR", 13: "LTE", 19: "LTE-A", 3: "UMTS", 8: "HSDPA",
            9: "HSUPA", 10: "HSPA", 2: "EDGE", 1: "GPRS", 4: "CDMA", 5: "EVDO"
        }
        gen = GEN.get(int(ntype), str(ntype))
    except Exception:
        pass
    try:
        cells = tm.getAllCellInfo()
        if cells and len(cells) > 0:
            # try LTE/NR first
            for ci in cells:
                cls = str(ci.getClass().getSimpleName())
                strength = None
                if cls == "CellInfoNr":
                    strength = ci.getCellSignalStrength().getDbm()
                elif cls == "CellInfoLte":
                    strength = ci.getCellSignalStrength().getDbm()
                elif cls == "CellInfoWcdma":
                    strength = ci.getCellSignalStrength().getDbm()
                elif cls == "CellInfoGsm":
                    strength = ci.getCellSignalStrength().getDbm()
                if strength is not None:
                    cell_dbm = int(strength)
                    break
    except Exception:
        pass

    wifi_ssid = None; wifi_bssid = None; wifi_rssi = None; wifi_speed = None
    try:
        info = wifi.getConnectionInfo()
        if info:
            ssid = info.getSSID()
            wifi_ssid = ssid.strip('"') if ssid else None
            wifi_bssid = info.getBSSID()
            wifi_rssi = int(info.getRssi()) if info.getRssi() is not None else None
            wifi_speed = int(info.getLinkSpeed()) if info.getLinkSpeed() is not None else None
    except Exception:
        pass

    return {
        "platform": "android",
        "active_transport": active or "UNKNOWN",
        "local_ip": _local_ip(),
        "cell_operator": operator,
        "plmn": plmn,
        "cell_generation": gen,
        "cell_signal_dbm": cell_dbm,
        "wifi_ssid": wifi_ssid,
        "wifi_bssid": wifi_bssid,
        "wifi_rssi": wifi_rssi,
        "wifi_link_mbps": wifi_speed,
    }

def _desktop_snapshot():
    return {
        "platform": sys.platform,
        "active_transport": "UNKNOWN",
        "local_ip": _local_ip(),
        "cell_operator": None,
        "plmn": None,
        "cell_generation": None,
        "cell_signal_dbm": None,
        "wifi_ssid": None,
        "wifi_bssid": None,
        "wifi_rssi": None,
        "wifi_link_mbps": None,
    }

def get_network_snapshot():
    try:
        import jnius  # noqa: F401
        return _android_snapshot()
    except Exception:
        return _desktop_snapshot()
