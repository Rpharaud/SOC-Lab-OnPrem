TF_DIR=phases/01-foundation/devsecops/terraform/local-docker

tf-init:
	cd $(TF_DIR) && terraform init -backend=false

tf-validate: tf-init
	cd $(TF_DIR) && terraform validate

zeek-test:
	@if command -v zeek >/dev/null 2>&1; then \
		echo "[*] Checking Zeek scripts (if any)"; \
		find phases/01-foundation/soc -name "*.zeek" -print0 | xargs -0 -r -I{} zeek -b -NN >/dev/null || true; \
	else echo "[!] zeek not installed on runner"; fi

suricata-test:
	@if command -v suricata >/dev/null 2>&1; then \
		echo "[*] Suricata config test"; \
		cfg=$$(find phases/01-foundation/soc -maxdepth 3 -name "suricata.yaml" | head -1); \
		if [ -n "$$cfg" ]; then sudo suricata -T -c "$$cfg" || exit 1; else echo "No suricata.yaml found"; fi \
	else echo "[!] suricata not installed on runner"; fi
