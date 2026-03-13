from app.search import search_logs


if __name__ == "__main__":
    query = input("Enter investigation query: ").strip()
    results = search_logs(query, limit=5)

    print("\nTop matches:\n")

    for item in results:
        payload = item["payload"]

        severity = payload.get("final_severity") or payload.get("severity") or "unknown"
        original_severity = payload.get("severity", "unknown")
        risk_score = payload.get("risk_score", 0)

        print(f"Vector Score: {item['score']:.4f}")
        print(f"Risk Score: {risk_score}")
        print(f"Severity: {severity}")
        print(f"Original Severity: {original_severity}")
        print(f"Event: {payload.get('event_text')}")
        print(f"Source: {payload.get('source')}")
        print(f"Type: {payload.get('event_type')}")
        print(f"Host: {payload.get('host')}")
        print(f"Username: {payload.get('username')}")
        print(f"Source IP: {payload.get('src_ip')}")
        print(f"Destination IP: {payload.get('dest_ip')}")
        print(f"Signature: {payload.get('signature')}")
        print(f"Category: {payload.get('category')}")
        print(f"MITRE Matches: {payload.get('mitre_matches')}")
        print(f"Indicators: {payload.get('indicators')}")
        print(f"Score Reasons: {payload.get('score_reasons')}")
        print(f"Threat Intel: {payload.get('threat_intel')}")
        print("-" * 70)
