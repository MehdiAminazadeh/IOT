"""
Anomaly Detection for Device Login Attempts (IoT / Auth Logs)
Date: 13.04.2023

Flag suspicious login rows (e.g., bursts of failures from many IPs,
rare devices/countries for a user, odd timing) using:
- Simple, interpretable features
- IsolationForest (unsupervised)
- A complementary rule-based check
"""

from __future__ import annotations
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


def make_toy_login_log(n_rows: int = 6000, seed: int = 42) -> pd.DataFrame:
    """
    Build a toy login log table. Replace this with real logs.
    Columns: ts, user, device, ip, country, success
    """
    rng = np.random.default_rng(seed)

    users = [f"user_{i}" for i in range(50)]
    devices = [f"dev_{i}" for i in range(40)]
    countries = ["DE", "NL", "FR", "ES", "US", "CN"]

    
    base_time = pd.Timestamp("2023-04-13 00:00:00")
    # 10 days of activity, minute granularity
    ts = base_time + pd.to_timedelta(rng.integers(0, 60 * 24 * 10, size=n_rows), unit="m")

    df = pd.DataFrame({
        "ts": ts,
        "user": rng.choice(users, n_rows),
        "device": rng.choice(devices, n_rows),
        "ip": [f"192.168.{rng.integers(0,256)}.{rng.integers(1,255)}" for _ in range(n_rows)],
        "country": rng.choice(countries, n_rows, p=[0.35, 0.10, 0.20, 0.10, 0.20, 0.05]),
        "success": (rng.random(n_rows) > 0.12).astype(int),  # mostly successes
    })

    
    anom_idx = rng.choice(df.index, 80, replace=False)
    df.loc[anom_idx, "success"] = 0
    df.loc[anom_idx, "ip"] = [
        f"10.{rng.integers(0,256)}.{rng.integers(0,256)}.{rng.integers(1,255)}" for _ in range(len(anom_idx))
    ]
    df.loc[anom_idx, "country"] = rng.choice(["US", "CN"], len(anom_idx))

    return df.sort_values("ts").reset_index(drop=True)


# -----------------------------------------------------------------------------
# 2) Feature engineering: keep it simple and meaningful
# -----------------------------------------------------------------------------
def add_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Numeric features suitable for anomaly detection.
    Works row-wise but uses short-time aggregates for context.
    """
    out = df.copy()
    out["minute"] = out["ts"].dt.floor("min")
    out["hour"] = out["ts"].dt.hour

    
    out["hour_sin"] = np.sin(2 * np.pi * out["hour"] / 24)
    out["hour_cos"] = np.cos(2 * np.pi * out["hour"] / 24)

    
    minute_agg = (
        out.groupby(["user", "minute"])
           .agg(
               attempts=("success", "size"),
               fail_ratio=("success", lambda s: 1 - s.mean()),
               uniq_ips=("ip", "nunique"),
               uniq_devices=("device", "nunique"),
               uniq_countries=("country", "nunique"),
           )
           .reset_index()
    )
    out = out.merge(minute_agg, on=["user", "minute"], how="left")

    # Time since last successful login (per user)
    out["ts_sec"] = out["ts"].view("int64") // 10**9
    last_success = {}
    secs_since_last_success = []
    for _, row in out.iterrows():
        u = row["user"]
        t = row["ts_sec"]
        prev = last_success.get(u, None)
        secs_since_last_success.append(0 if prev is None else t - prev)
        if row["success"] == 1:
            last_success[u] = t
    out["secs_since_last_success"] = np.array(secs_since_last_success, dtype=float)

    
    uc = out.groupby(["user", "country"]).size().rename("uc_count")
    ud = out.groupby(["user", "device"]).size().rename("ud_count")
    out = out.join(uc, on=["user", "country"]).join(ud, on=["user", "device"])
    out[["uc_count", "ud_count"]] = out[["uc_count", "ud_count"]].fillna(0)
    out["rare_country_for_user"] = (out["uc_count"] < 3).astype(int)
    out["rare_device_for_user"] = (out["ud_count"] < 3).astype(int)


    feat_cols = [
        "attempts", "fail_ratio", "uniq_ips", "uniq_devices", "uniq_countries",
        "hour_sin", "hour_cos",
        "secs_since_last_success",
        "rare_country_for_user", "rare_device_for_user",
    ]
    out[feat_cols] = out[feat_cols].fillna(0)
    return out, feat_cols



def detect_anomalies(
    df_feat: pd.DataFrame,
    feat_cols: list[str],
    contamination: float = 0.02,
    seed: int = 0
) -> pd.DataFrame:
    """
    Train an unsupervised detector and label rows with anomaly flags.
    """
    X = df_feat[feat_cols].values

    iso = IsolationForest(
        n_estimators=300,
        contamination=contamination,
        random_state=seed,
    ).fit(X)

    scores = -iso.score_samples(X)        # higher => more anomalous
    df_out = df_feat.copy()
    df_out["anomaly_score"] = scores

    # Threshold by percentile (matches contamination roughly)
    thr = np.quantile(scores, 1 - contamination)
    df_out["ml_flag"] = (scores >= thr).astype(int)

    df_out["rule_flag"] = ((df_out["fail_ratio"] > 0.8) & (df_out["uniq_ips"] >= 5)).astype(int)

    
    df_out["final_flag"] = (df_out["ml_flag"] | df_out["rule_flag"]).astype(int)
    return df_out


if __name__ == "__main__":
    #Data
    raw = make_toy_login_log()

    #Features
    df_feat, features = add_features(raw)

    #Detect
    flagged = detect_anomalies(df_feat, features, contamination=0.02)

   
    review_cols = [
        "ts", "user", "device", "ip", "country", "success",
        "attempts", "fail_ratio", "uniq_ips", "uniq_devices",
        "secs_since_last_success", "anomaly_score", "ml_flag", "rule_flag", "final_flag"
    ]
    print(
        flagged.loc[flagged["final_flag"] == 1, review_cols]
               .sort_values("anomaly_score", ascending=False)
               .head(20)
               .to_string(index=False)
    )
