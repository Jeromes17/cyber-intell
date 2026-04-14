# CyberIntell (C0R3 Security)

## Overview

CyberIntell is a hybrid endpoint threat detection framework designed to identify both known and unknown cyber threats using behavior-driven analysis. The system integrates rule-based detection, heuristic analysis, and machine learning to provide real-time monitoring and intelligent alerting.

## Key Features

* Hybrid Detection Engine (Rule + Heuristic + ML)
* Real-time Telemetry Ingestion
* Single-Alert Prioritization (reduces alert fatigue)
* Interactive Dashboard for visualization
* Scalable Queue-based Processing

## Architecture

* **Phase 1**: Local Endpoint Monitoring  
  (Process, File Integrity, Network Behavior)
* **Phase 2**: Telemetry Ingestion & Async Processing  
* **Detection Layer**: Multi-layer threat evaluation  
* **Visualization Layer**: Dashboard Interface  

## Tech Stack

* Python (Flask)
* SQLite
* Queue-based Workers
* Machine Learning (Isolation Forest)
* REST APIs

## Project Structure

```bash
(Add your tree output here)
