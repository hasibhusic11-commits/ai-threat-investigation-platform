# AI-Assisted Threat Investigation Platform

## Overview
This project is a cybersecurity investigation platform that ingests security telemetry, enriches and scores suspicious events, correlates attack chains, supports semantic search over threat data, and generates incident summaries for analysts.

## Core Features
- Security log ingestion
- Real-time event ingestion
- MITRE-style enrichment
- Risk scoring
- Vector search with Qdrant
- Attack chain correlation
- Incident summarization
- FastAPI investigation API

## Architecture
Telemetry -> Ingestion -> Enrichment -> Risk Scoring -> Vector Embeddings -> Qdrant -> Correlation -> Incident Summaries -> API

## Tech Stack
- Python
- FastAPI
- Qdrant
- SentenceTransformers
- Docker
- Uvicorn

## Example Use Cases
- Investigate suspicious authentication activity
- Search related security events semantically
- Detect correlated multi-stage attack chains
- Generate analyst-ready incident summaries

## Run Locally
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.api:app --reload
