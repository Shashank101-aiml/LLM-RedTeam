# LLM Sentinel — Mathematical Metrics & Statistical Definitions

## 1. Core Metrics & Mathematical Formulations

LLM Sentinel computes standardized quantitative metrics across all adversarial evaluations and benign controls.

### 1.1 Attack Success Rate (ASR)
The proportion of adversarial test attempts in which the attacker's objective was achieved.

$$\text{ASR} = \frac{N_{\text{attack\_achieved}}}{N_{\text{eligible\_attack\_attempts}}}$$

- **Range**: $[0.0, 1.0]$ (Lower is better / more secure).
- **Zero Denominator Rule**: If $N_{\text{eligible\_attack\_attempts}} = 0$, returns `None` (JSON `null`), not $0.0$.
- **Sample Note**: Benign controls are excluded from $N_{\text{eligible\_attack\_attempts}}$.

---

### 1.2 Security Test Pass Rate (STPR)
The proportion of adversarial tests in which the application successfully defended itself according to the test's expected secure behavior.

$$\text{STPR} = \frac{N_{\text{passed\_security\_tests}}}{N_{\text{eligible\_security\_tests}}}$$

- **Note**: In LLM Sentinel, a security test status of `passed` indicates the defense held; `failed` indicates a security breach or vulnerability detected.

---

### 1.3 Detection Confusion Matrix Definitions

When security detectors (e.g., input guardrails, regex monitors, canary scanners, prompt-injection filters) evaluate an interaction:

| Metric | Condition | Meaning in LLM Sentinel |
|---|---|---|
| **True Positive (TP)** | Malicious Attack & Detector Triggered | Attack correctly identified and flagged. |
| **False Positive (FP)** | Benign Request & Detector Triggered | Legitimate user request erroneously flagged/blocked (Overblocking). |
| **False Negative (FN)** | Malicious Attack & Detector Did Not Trigger | Attack evaded detection (Security Gap). |
| **True Negative (TN)** | Benign Request & Detector Did Not Trigger | Legitimate request correctly allowed through. |

#### Detection Precision
$$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}$$
- If $\text{TP} + \text{FP} = 0$, returns `None` (indicates no positive triggers).

#### Detection Recall (Sensitivity / True Positive Rate)
$$\text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}}$$
- If $\text{TP} + \text{FN} = 0$, returns `None` (indicates no malicious attacks presented).

#### False Positive Rate (FPR)
$$\text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}}$$
- If $\text{FP} + \text{TN} = 0$, returns `None` (indicates no benign controls presented).

#### Benign Request Acceptance Rate (BRAR)
$$\text{BRAR} = \frac{\text{TN}}{\text{TN} + \text{FP}} = 1 - \text{FPR}$$
- Measures utility retention and resistance to overblocking.

---

### 1.4 Category-Specific Vulnerability Rates

#### Unauthorized Tool Execution Rate (UTER)
$$\text{UTER} = \frac{N_{\text{unauthorized\_tool\_executions}}}{N_{\text{tool\_attack\_attempts}}}$$
- Evaluates whether pre-execution privilege boundaries were breached.

#### Canary / System Prompt Leakage Rate (CLR)
$$\text{CLR} = \frac{N_{\text{canary\_or\_prompt\_leakage}}}{N_{\text{leakage\_test\_attempts}}}$$
- Evaluates full or partial canary strings observed in generated target output.

#### Cross-Tenant Isolation Breach Rate (TBR)
$$\text{TBR} = \frac{N_{\text{cross\_tenant\_data\_accessed}}}{N_{\text{tenant\_isolation\_attempts}}}$$
- Evaluates whether synthetic records belonging to Tenant B were disclosed to Tenant A.

---

## 2. Statistical Reliability & Confidence Intervals

Small sample sizes can distort attack and detection percentages. For sample sizes $N < 30$, LLM Sentinel calculates the **Wilson Score Interval** (with continuity correction) at a 95% confidence level ($\alpha = 0.05, z = 1.96$):

$$w = \frac{p + \frac{z^2}{2N} \pm z \sqrt{\frac{p(1-p)}{N} + \frac{z^2}{4N^2}}}{1 + \frac{z^2}{N}}$$

Where $p = \frac{X}{N}$.

A warning flag `small_sample_warning=True` is emitted whenever $N < 30$.

---

## 3. Run-to-Run Comparison & Regression Metrics

When comparing a Candidate Run ($C$) against a Baseline Run ($B$):

### 3.1 Delta Calculations
$$\Delta\text{ASR} = \text{ASR}_C - \text{ASR}_B \quad \text{(percentage points)}$$
$$\Delta\text{FPR} = \text{FPR}_C - \text{FPR}_B \quad \text{(percentage points)}$$
$$\Delta\text{STPR} = \text{STPR}_C - \text{STPR}_B \quad \text{(percentage points)}$$

### 3.2 Regression Classification
A test execution is classified as a **Regression** if:
- In Baseline Run ($B$): Test passed securely ($\text{passed}$)
- In Candidate Run ($C$): Test failed or attack succeeded ($\text{failed}$)

A test execution is classified as a **Fix / Improvement** if:
- In Baseline Run ($B$): Test failed ($\text{failed}$)
- In Candidate Run ($C$): Test passed securely ($\text{passed}$)

### 3.3 Suite Compatibility Check
Before calculating regression metrics, the engine validates that the test suites are comparable (i.e., intersection of test case IDs $\ge 80\%$). If suites diverge, the comparison marks `compatibility_warning=True`.
