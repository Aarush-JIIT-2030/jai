# Security & Ethical Defense Disclosure

## Operational Scope

CyberSentinel is an **offline network-flow analysis and replay prototype**:
1. **No Live Interception:** The system does not sniff live packets, promiscuously monitor interfaces, or intercept real network traffic.
2. **No Active Exploits:** The system does not mount attacks, probe external networks, or test vulnerabilities.
3. **Simulated Enforcement:** Decisions (`ALLOW`, `BLOCK`, `REVIEW`) are simulated recommendations for SOC analysts and network replay simulations. The software does not modify system firewalls (iptables, nftables, Windows Defender Firewall) or route tables.

## Data Privacy & Integrity

1. **Identifier Exemption:** Sequential network identifiers (`record_id`) and private IP addresses are strictly excluded from predictive features to prevent identification leakage and shortcut learning.
2. **Evaluation Purity:** The official evaluation holdout set is never used for model training, scaler fitting, or hyperparameter selection.
3. **No Hardcoded Metrics:** The platform exposes genuine model inference and evaluation reports computed directly on challenge data.
4. **Secret Protection:** Secrets, database tokens, and private keys are never committed to Git or exposed via frontend client builds.
