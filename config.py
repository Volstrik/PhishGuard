# config.py

import os

class Config:
    # ----------------------------
    # VirusTotal API
    # ----------------------------
    VIRUSTOTAL_API_KEY = os.environ.get("VT_API_KEY", "dee4d2d0253fa878154185c0ef298ac80d055e5122f0fb15844ab3a537b9e52f")
    VIRUSTOTAL_URL     = "https://www.virustotal.com/api/v3/urls"

    # ----------------------------
    # Flask
    # ----------------------------
    SECRET_KEY = os.environ.get("SECRET_KEY", "phishguard-super-secret-key-2026")
    DEBUG      = True

    # ----------------------------
    # Database
    # ----------------------------
    DATABASE_NAME = "phishguard.db"

    # ----------------------------
    # Admin Secret Key
    # Typed into hidden field on login page after Ctrl+Shift+A
    # ----------------------------
    ADMIN_SECRET_KEY = os.environ.get("ADMIN_SECRET_KEY", "PG-ADMIN-2026-ULTRA")

    # ----------------------------
    # Flask-Login
    # ----------------------------
    LOGIN_VIEW          = "login"
    REMEMBER_COOKIE_DAYS = 7