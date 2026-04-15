import os
import joblib
import pandas as pd
import numpy as np
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
import logging

from sqlalchemy.orm import Session
from models import LogDB
from feature_translator import FeatureTranslator

# =====================================================================
# GLOBAL IN-MEMORY ML ARTIFACTS
# =====================================================================
model = None
scaler = None
tfidf = None
svd = None
features_list = None
translator = None
threshold = -0.0900 # PFE Calibrated Override

# =====================================================================
# HIGH-SPEED IN-MEMORY STATE TRACKING (Zero DB-I/O for Sliding Windows)
# =====================================================================
# We store timestamps of errors by (project_id, type) to calculate rolling counts fast.
# error_history[project_id][log_type] = deque([...timestamps...])
error_history = defaultdict(lambda: defaultdict(deque))

# Hardware Metrics Tracking (for CPU/RAM Velocity)
hw_history = defaultdict(lambda: defaultdict(deque))

# Cumulative Sum (CUSUM) Tracker (Tracks drift natively)
cusum_tracker = defaultdict(lambda: defaultdict(float))
ERROR_MEAN = 0.20 # Approximate baseline probability of an error event

logger = logging.getLogger("ml_service")

def load_ml_artifacts(artifacts_path: str = "ml_artifacts"):
    """
    Loads Scikit-Learn .pkl instances into global RAM natively once at boot.
    """
    global model, scaler, tfidf, svd, features_list, translator
    
    try:
        model = joblib.load(os.path.join(artifacts_path, "model_final.pkl"))
        scaler = joblib.load(os.path.join(artifacts_path, "scaler_final.pkl"))
        tfidf = joblib.load(os.path.join(artifacts_path, "tfidf_final.pkl"))
        svd = joblib.load(os.path.join(artifacts_path, "svd_final.pkl"))
        features_list = joblib.load(os.path.join(artifacts_path, "features_final.pkl"))
        translator = FeatureTranslator(tfidf=tfidf, svd=svd, features_list=features_list)
        logger.info(f"✅ ML Engine Activated. Loaded {len(features_list)} features schema.")
    except Exception as e:
        logger.error(f"❌ ML Engine Failed to load: {e}. Check machine learning artifacts.")

def _cleanup_old_state(project_id: int, log_type: str, current_time: datetime):
    """
    Purges timestamps older than 60 minutes from the high-speed deques.
    """
    cutoff_60m = current_time - timedelta(minutes=60)
    
    # Clean Error Deque
    err_dq = error_history[project_id][log_type]
    while err_dq and err_dq[0] < cutoff_60m:
        err_dq.popleft()
        
    # Clean Hardware Deque
    hw_dq = hw_history[project_id][log_type]
    while hw_dq and hw_dq[0][0] < cutoff_60m:
        hw_dq.popleft()

def calculate_time_features(timestamp: datetime) -> tuple:
    hour = timestamp.hour
    day = timestamp.weekday()
    hour_sin = np.sin(2 * np.pi * hour / 24.0)
    hour_cos = np.cos(2 * np.pi * hour / 24.0)
    day_sin = np.sin(2 * np.pi * day / 7.0)
    day_cos = np.cos(2 * np.pi * day / 7.0)
    return hour_sin, hour_cos, day_sin, day_cos

def process_log_anomaly(log_id: int, timestamp: datetime, level: str, log_type: str, message: str, cpu: float, ram: float, project_id: int, project_name: str):
    """
    The Non-Blocking Background ML Inference Pipeline.
    Constructs the 25 features entirely in RAM instantly without locking the database.
    Opens its own localized DB session to act entirely autonomously behind the HTTP response.
    """
    if not model or translator is None:
        # Fallback if AI is offline
        return

    from main import SessionLocal
    db = SessionLocal()
    try:
        # Ensure timezone awareness matches DB
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        is_error = 1 if level.upper() in ["ERROR", "CRITICAL", "WARNING"] else 0

        # ---------------------------------------------------------
        # 1. State Maintenance & High-Speed Sliding Windows
        # ---------------------------------------------------------
        _cleanup_old_state(project_id, log_type, timestamp)

        # Append to running memory
        if is_error:
            error_history[project_id][log_type].append(timestamp)
        hw_history[project_id][log_type].append((timestamp, cpu or 0.0, ram or 0.0))

        # Calculate Rolling Windows via Array Traversing
        err_dq = error_history[project_id][log_type]
        
        cnt_30s = sum(1 for t in err_dq if t >= timestamp - timedelta(seconds=30))
        cnt_1m  = sum(1 for t in err_dq if t >= timestamp - timedelta(minutes=1))
        cnt_5m  = sum(1 for t in err_dq if t >= timestamp - timedelta(minutes=5))
        cnt_10m = sum(1 for t in err_dq if t >= timestamp - timedelta(minutes=10))
        cnt_15m = sum(1 for t in err_dq if t >= timestamp - timedelta(minutes=15))
        cnt_60m = len(err_dq) # Pruned exactly to 60m

        # CUSUM Drift Tracking Engine
        cusum_tracker[project_id][log_type] = max(0.0, cusum_tracker[project_id][log_type] + float(is_error) - ERROR_MEAN)
        cusum_score = cusum_tracker[project_id][log_type]

        # Ratio Architectures
        short_long = (cnt_1m / cnt_60m) if cnt_60m > 0 else 0.0
        mid_long   = (cnt_15m / cnt_60m) if cnt_60m > 0 else 0.0
        error_trend = (cnt_5m - cnt_15m) / 10.0
        dens_5m    = cnt_5m / 5.0
        dens_15m   = cnt_15m / 15.0

        # Hardware Velocity
        hw_dq = hw_history[project_id][log_type]
        cpu_vel, ram_vel = 0.0, 0.0
        if len(hw_dq) > 1:
            oldest_ts, oldest_cpu, oldest_ram = hw_dq[0]
            time_diff = (timestamp - oldest_ts).total_seconds() / 60.0
            if time_diff > 0:
                cpu_vel = ((cpu or 0.0) - oldest_cpu) / time_diff
                ram_vel = ((ram or 0.0) - oldest_ram) / time_diff

        # ---------------------------------------------------------
        # 2. Vectorized ML Engineering (NLP & Trig Arrays)
        # ---------------------------------------------------------
        hour_sin, hour_cos, day_sin, day_cos = calculate_time_features(timestamp)
        
        # Map directly matching PFE standard feature list
        base_feature_dict = {
            "is_error": is_error,
            "Errors_Last_30s": cnt_30s,
            "Errors_Last_1_Min": cnt_1m,
            "Errors_Last_5_Min": cnt_5m,
            "Errors_Last_10_Min": cnt_10m,
            "Errors_Last_15_Min": cnt_15m,
            "Errors_Last_60_Min": cnt_60m,
            "CUSUM_Errors": cusum_score,
            "Short_Long_Ratio": short_long,
            "Mid_Long_Ratio": mid_long,
            "Error_Trend_Slope": error_trend,
            "Error_Density_5Min": dens_5m,
            "Error_Density_15Min": dens_15m,
            "CPU_Velocity": cpu_vel,
            "RAM_Velocity": ram_vel,
            "Hour_sin": hour_sin,
            "Hour_cos": hour_cos,
            "Day_sin": day_sin,
            "Day_cos": day_cos,
        }

        # Translate runtime values into model-ready frame with exact feature names/order.
        try:
            model_frame = translator.build_model_frame(
                base_features=base_feature_dict,
                log_type=log_type,
                message=message,
            )
            vector_scaled = scaler.transform(model_frame)
            score = model.decision_function(vector_scaled)[0]
        except Exception as e:
            logger.error(f"Inference Mapping Error: {e}")
            return

        # ---------------------------------------------------------
        # 3. Notification & Database Labeling Hooks
        # ---------------------------------------------------------
        if score < threshold:
            # 1. Label the Database asynchronously
            log_obj = db.query(LogDB).filter(LogDB.id == log_id).first()
            if log_obj:
                log_obj.is_anomaly = True
                db.commit()

            # 2. Call Notification Engine
            from notifications import send_critical_alert_email
            log_details = f"Score: {score:.4f} | Threshold: {threshold}\nLevel: {level}\nMessage: {message}\nCPU: {cpu or 0.0:.1f}% | RAM: {ram or 0.0:.1f}%"
            send_critical_alert_email("NEO-AI", project_name, log_details)
            
    finally:
        db.close()
