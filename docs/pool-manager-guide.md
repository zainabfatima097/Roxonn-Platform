# Roxonn Platform: Pool Manager Manual

## Overview
Pool Managers are project maintainers who fund repositories to attract quality contributors. This manual explains how to use Roxonn as a Pool Manager to fund your open-source projects and manage contributor rewards.

---

## Table of Contents

<details>
<summary><strong>Click to expand</strong></summary>

- [Getting Started](#getting-started)
- [Repository Registration](#repository-registration)
- [Funding Your Repository](#funding-your-repository)
- [Managing Rewards](#managing-rewards)
- [Working with Contributors](#working-with-contributors)
- [Advanced Features](#advanced-features)
- [Troubleshooting](#troubleshooting)

</details>

---

## Getting Started

### Prerequisites
- A GitHub account  
- A repository you maintain (public or private)  
- XDC wallet with funds (**XDC**, **ROXN**, or **USDC**)  
- Basic understanding of pull requests and code review  

---

### Registration Process
1. **Visit the Platform**  
   Go to [app.roxonn.com](https://app.roxonn.com)

2. **Connect GitHub**  
   Authorize Roxonn to access your GitHub account

3. **Wallet Setup**  
   The system automatically generates an XDC wallet for you

4. **Complete Profile**  
   Add any additional information related to your project

---
## Repository Registration

### Step 1: Register Your Repository
1. From your dashboard, click **Register Repository**
2. Select the GitHub repository you want to fund
3. Configure repository settings:
   - **Repository Visibility**: Public or Private
   - **Contribution Types**: Choose which types of contributions qualify (bug fixes, features, documentation, tests, etc.)
   - **Minimum PR Requirements**: Define quality standards for contributions
   - **Auto-approval**: Enable or disable automatic reward distribution

---

### Step 2: Configure Repository Settings

**Example Repository Configuration**
```yaml
repository:
  name: "your-project-name"
  funding_token: "XDC"  # or "ROXN", "USDC"
  bounty_types:
    - bug_fixes
    - features
    - documentation
    - tests
  requirements:
    min_tests: 80%      # Minimum test coverage
    code_review: true   # Requires code review
    ci_passing: true    # Requires CI to pass
```

---

## Funding Your Repository

### Funding Options

Roxonn supports the following tokens for funding repositories:

1. **XDC** – Native token of the XDC Network  
2. **ROXN** – Roxonn platform token  
3. **USDC** – Stablecoin  

---

### How to Fund

#### Step 1: Access Repository Dashboard
- Navigate to your registered repository from the dashboard
- Click **“Fund Repository”**

#### Step 2: Choose Funding Method
- **One-time Funding** – Add a lump sum to the repository pool  
- **Recurring Funding** – Set up automatic monthly funding  
- **Per-Issue Funding** – Fund specific issues individually  

#### Step 3: Set Funding Amount

```javascript
// Example funding structure
const funding = {
  total_pool: "1000 XDC",
  distribution: {
    bug_fixes: "50 XDC",
    small_features: "100 XDC",
    major_features: "500 XDC",
    documentation: "50 XDC"
  }
};
```
---

### Funding Strategies

- **Balanced Pool**  
  Distribute funds evenly across all issue types to encourage broad participation.

- **Priority-Based Allocation**  
  Allocate higher rewards to high-priority or critical issues.

- **Bounty Multipliers**  
  Apply reward multipliers for:
  - Urgent issues
  - Complex problems
  - First-time contributors

---

## Managing Rewards

### Setting Reward Amounts

1. **Default Rewards**  
   Set baseline reward amounts for different contribution types (bugs, features, docs, etc.).

2. **Dynamic Rewards**  
   Configure reward formulas based on:
   - PR complexity
   - Code quality
   - Time to completion
   - Contributor reputation

---

### Reward Distribution Rules

```yaml
rewards:
  distribution:
    - trigger: "PR merged"
      conditions:
        - "tests_passing: true"
        - "review_approved: true"
        - "no_conflicts: true"
      action: "auto_pay 80%"
    
    - trigger: "30 days after merge"
      conditions:
        - "no_bugs_reported: true"
      action: "pay_remaining 20%"
```

---

### Manual Overrides

As a Pool Manager, you can:

- Adjust reward amounts before payment
- Split rewards among multiple contributors
- Withhold payment for substandard or incomplete work
- Add bonus rewards for exceptional contributions

---

## Working with Contributors

### Attracting Contributors

1. **Well-Documented Issues**  
   Ensure issues include clear descriptions, acceptance criteria, and expected outcomes.

2. **Progressive Bounties**  
   Increase bounty amounts for issues that remain open for longer periods.

3. **Beginner-Friendly Issues**  
   Label selected issues as **“good first issue”** to attract new contributors.

---

## Review Process

### Code Review Guidelines

- Check overall code quality and adherence to project standards
- Verify that appropriate tests are included and passing
- Ensure relevant documentation is updated
- Confirm that no unintended breaking changes are introduced

---

### Communication Best Practices

- Provide clear and constructive feedback
- Set expectations early and transparently
- Be responsive to contributor questions and clarifications
- Acknowledge and appreciate high-quality contributions

---

## Payment Automation

Roxonn automatically handles reward distribution when all of the following conditions are met:

1. The pull request passes all required checks (CI, tests, linting, etc.)
2. The minimum number of required code reviews is completed
3. The pull request is merged into the main branch
4. No disputes are raised within the configured dispute period

Once these conditions are satisfied, the reward is released to the contributor on-chain without any manual intervention.

---

## Advanced Features

### Multi-Signature Wallets

For larger projects or organizations, Pool Managers can configure **multi-signature (multi-sig) wallets** to enhance security.

With multi-sig wallets:
- Multiple maintainers must approve reward payments
- No single maintainer can unilaterally release funds
- Payments are executed only after the required number of signatures is collected

This setup is recommended for high-value repositories or shared treasury management.



