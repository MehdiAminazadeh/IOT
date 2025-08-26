# Anomaly Detection for Device Login Attempts (IoT) — README

> Compact demo that logs login attempts on `127.0.0.1` and detects anomalies (e.g., failure bursts, unusual IP/device/country patterns) using simple features + IsolationForest.  
> Demo timeline for synthetic data is anchored at **13.04.2023**.

---

## 📌 Features

- **Local login endpoint** (`POST /login`) on `127.0.0.1:5000`
- **CSV logging** (`login_log.csv`) compatible with the anomaly detector
- **Unsupervised anomaly detection** via `IsolationForest`
- **Rule-based checks** (e.g., many failures + many distinct IPs in short time)
- **Readable, minimal code** with few dependencies

---
