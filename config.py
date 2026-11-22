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