# Nexus IDS – Real-Time Network Intrusion Detection System

A real-time Intrusion Detection System (IDS) built using Go, Python, and Machine Learning. It captures live network traffic, analyzes behavior per IP, detects anomalies, and streams results to a real-time dashboard.

---

## Overview

Nexus IDS is a hybrid security monitoring system that:

- Captures live network packets using Go (gopacket)
- Extracts per-IP behavioral features
- Sends data to a Python ML engine
- Uses Isolation Forest for anomaly detection
- Streams results via WebSockets
- Displays live traffic in a web dashboard

---

---

## Dashboard Preview

![Dashboard](https://i.imgur.com/5QYNdNI.jpeg)

---

## Features

- Real-time packet capture
- Per-IP traffic tracking
- ML-based anomaly detection
- WebSocket streaming system
- Attack classification (FLOOD, PORT_SCAN, BRUTE_FORCE)
- Lightweight web dashboard
- Go + Python hybrid architecture

---

## Tech Stack

**Backend (Go)**
- gopacket
- pcap
- WebSockets

**ML Engine (Python)**
- FastAPI / websockets
- NumPy
- PyOD (Isolation Forest)

**Frontend**
- HTML
- CSS
- JavaScript
- WebSocket API

---

## Installation

### Clone repository
```bash
git clone https://github.com/y33b/packet_engine.git
cd packet_engine
