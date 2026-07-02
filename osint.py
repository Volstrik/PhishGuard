# osint.py

import ssl
import socket
import whois
import threading
from datetime import datetime
from urllib.parse import urlparse


def extract_domain(url):
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    domain = domain.replace("www.", "").split(":")[0].split("/")[0]
    return domain


def _run_with_timeout(func, args=(), timeout=5):
    """
    Cross-platform timeout using a thread instead of signal.alarm
    (signal.alarm doesn't exist on Windows).
    Returns (result, timed_out_bool).
    """
    result = {"value": None, "error": None}

    def target():
        try:
            result["value"] = func(*args)
        except Exception as e:
            result["error"] = e

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout)

    if thread.is_alive():
        return None, True  # timed out — thread abandoned, daemon so it won't block exit
    if result["error"]:
        return None, False  # raised an error, not a timeout
    return result["value"], False


def get_whois_info(domain):
    def _lookup():
        return whois.whois(domain)

    w, timed_out = _run_with_timeout(_lookup, timeout=5)

    if timed_out or w is None:
        return {
            "available":     False,
            "registrar":     "Unavailable",
            "created_date":  "Unavailable",
            "age_days":      None,
            "age_label":     "Could not retrieve",
            "is_new_domain": False
        }

    try:
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]

        registrar = w.registrar

        age_days  = None
        age_label = "Unknown"

        if created:
            age_days = (datetime.now() - created).days
            if age_days < 0:
                age_days = None
            else:
                if age_days < 30:
                    age_label = "Very New (High Risk Signal)"
                elif age_days < 180:
                    age_label = "New"
                elif age_days < 365:
                    age_label = "Under 1 Year"
                else:
                    years = age_days // 365
                    age_label = f"{years}+ Year{'s' if years > 1 else ''} Old"

        return {
            "available":     True,
            "registrar":     registrar or "Unknown",
            "created_date":  created.strftime("%d %b %Y") if created else "Unknown",
            "age_days":      age_days,
            "age_label":     age_label,
            "is_new_domain": age_days is not None and age_days < 90
        }

    except Exception:
        return {
            "available":     False,
            "registrar":     "Unavailable",
            "created_date":  "Unavailable",
            "age_days":      None,
            "age_label":     "Could not retrieve",
            "is_new_domain": False
        }


def get_ssl_info(domain):
    def _check():
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                return ssock.getpeercert()

    cert, timed_out = _run_with_timeout(_check, timeout=5)

    if timed_out or cert is None:
        return {
            "available":     True,
            "has_ssl":       False,
            "issuer":        None,
            "valid_from":    None,
            "valid_until":   None,
            "is_valid":      False,
            "days_left":     None,
            "expiring_soon": False
        }

    try:
        issuer_parts = dict(x[0] for x in cert.get("issuer", []))
        issuer_name  = issuer_parts.get("organizationName") or issuer_parts.get("commonName") or "Unknown"

        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        not_after  = datetime.strptime(cert["notAfter"],  "%b %d %H:%M:%S %Y %Z")
        now        = datetime.now()

        is_valid  = not_before <= now <= not_after
        days_left = (not_after - now).days

        return {
            "available":     True,
            "has_ssl":       True,
            "issuer":        issuer_name,
            "valid_from":    not_before.strftime("%d %b %Y"),
            "valid_until":   not_after.strftime("%d %b %Y"),
            "is_valid":      is_valid,
            "days_left":     days_left,
            "expiring_soon": is_valid and days_left < 14
        }

    except Exception:
        return {
            "available":     True,
            "has_ssl":       False,
            "issuer":        None,
            "valid_from":    None,
            "valid_until":   None,
            "is_valid":      False,
            "days_left":     None,
            "expiring_soon": False
        }


def calculate_osint_risk_modifier(whois_data, ssl_data):
    modifier = 0
    warnings = []

    if whois_data.get("is_new_domain"):
        modifier += 12
        warnings.append("Domain registered less than 90 days ago")

    if not ssl_data.get("has_ssl"):
        modifier += 8
        warnings.append("No valid SSL certificate found")
    elif ssl_data.get("expiring_soon"):
        modifier += 3
        warnings.append("SSL certificate expiring within 14 days")

    return min(modifier, 20), warnings