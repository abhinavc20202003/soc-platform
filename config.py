"""Central configuration for the Mini SOC platform."""
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent

APP_NAME = "AI-Powered Mini SOC"
APP_VERSION = "0.1.0"

DB_PATH = Path(os.getenv("SOC_DB_PATH", BASE_DIR / "database" / "soc.db"))
SAMPLE_LOG_DIR = BASE_DIR / "sample_logs"

# Detection thresholds (tuned in Phase 3)
BRUTE_FORCE_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))
BRUTE_FORCE_WINDOW_SECONDS = int(os.getenv("BRUTE_FORCE_WINDOW_SECONDS", "60"))

# Splunk HEC (configured in Phase 7; never hard-code tokens)
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")

# Detection rules (Phase 3)
FAIL_THEN_SUCCESS_MIN_FAILURES = int(os.getenv("FAIL_THEN_SUCCESS_MIN_FAILURES", "3"))
FAIL_THEN_SUCCESS_WINDOW_SECONDS = int(os.getenv("FAIL_THEN_SUCCESS_WINDOW_SECONDS", "300"))
DISTINCT_USER_THRESHOLD = int(os.getenv("DISTINCT_USER_THRESHOLD", "3"))
# Comma-separated known-bad IPs, e.g. SUSPICIOUS_IPS=198.51.100.7,198.51.100.8
SUSPICIOUS_IPS = {
    ip.strip() for ip in os.getenv("SUSPICIOUS_IPS", "").split(",") if ip.strip()
}
# ML anomaly detection (Phase 6)
ML_WINDOW_MINUTES = int(os.getenv("ML_WINDOW_MINUTES", "5"))   # must divide 60
ML_CONTAMINATION = float(os.getenv("ML_CONTAMINATION", "0.01"))
ML_ZSCORE_THRESHOLD = float(os.getenv("ML_ZSCORE_THRESHOLD", "3.0"))
ML_RANDOM_SEED = 42
OFF_HOURS_START = 22   # UTC hour from which logins count as off-hours
OFF_HOURS_END = 6      # UTC hour before which logins count as off-hours