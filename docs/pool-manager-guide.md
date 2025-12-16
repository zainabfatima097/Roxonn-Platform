# Roxonn Platform: Pool Manager Manual

## Overview
Pool Managers are project maintainers who fund repositories to attract quality contributors. This manual explains how to use **Roxonn** as a **Pool Manager** to fund your open-source projects and manage contributor rewards.

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

1. **XDC** - Native token of the XDC Network  
2. **ROXN** - Roxonn platform token  
3. **USDC** - Stablecoin  

---

### How to Fund

#### Step 1: Access Repository Dashboard
- Navigate to your registered repository from the dashboard
- Click **“Fund Repository”**

#### Step 2: Choose Funding Method
- **One-time Funding** - Add a lump sum to the repository pool  
- **Recurring Funding** - Set up automatic monthly funding  
- **Per-Issue Funding** - Fund specific issues individually  

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

```solidity
// Example multi-sig configuration
multisig:
  required_signatures: 2
  signers:
    - "0xMaintainer1"
    - "0xMaintainer2"
    - "0xMaintainer3"
```

---

### Staking for Pool Managers

Pool Managers can stake **ROXN tokens** to unlock additional platform benefits, including:

- Governance voting rights for platform-level decisions
- Discounts on platform fees
- Increased reputation and visibility within the Roxonn ecosystem

Staking helps establish long-term commitment and trust, especially for high-impact projects.

---

### Analytics Dashboard

The Analytics Dashboard provides insights into your repository’s performance and engagement.

You can track:

- **Contribution Metrics**
  - Number of pull requests submitted and merged
  - Lines of code added or modified
  - Issues resolved over time

- **Financial Metrics**
  - Total funds allocated
  - Rewards distributed to contributors
  - Current reward pool balance

- **Contributor Statistics**
  - Number of active contributors
  - Contributor retention rates
  - Overall contributor satisfaction scores

These insights help Pool Managers optimize funding strategies and contributor engagement.

---

### Integration with CI/CD

Roxonn integrates seamlessly with existing CI/CD pipelines to automate validation and reward eligibility.

Supported integrations allow you to:
- Require CI checks to pass before rewards are released
- Enforce test coverage and build success
- Ensure consistent code quality before payment automation triggers

This ensures rewards are only distributed for verified, high-quality contributions.
```yaml
# GitHub Actions Integration Example
name: Roxonn Bounty Verification
on:
  pull_request:
    types: [closed]
jobs:
  verify-and-pay:
    runs-on: ubuntu-latest
    if: github.event.pull_request.merged == true
    steps:
      - name: Verify Contribution
        uses: roxonn/verify-action@v1
        with:
          repo-token: ${{ secrets.GITHUB_TOKEN }}
          roxonn-token: ${{ secrets.ROXONN_TOKEN }}
      
      - name: Trigger Payment
        if: success()
        run: |
          curl -X POST https://api.roxonn.com/webhook/payment \
            -H "Authorization: Bearer ${{ secrets.ROXONN_TOKEN }}" \
            -d '{"pr_id": "${{ github.event.pull_request.id }}"}'
```
---
# Troubleshooting

## Common Issues and Solutions

### Issue: Payment Not Processing

**Symptoms:** PR merged but payment not sent

**Checklist:**
1. Verify repository has sufficient funds
2. Check if auto-payment is enabled
3. Confirm PR meets all requirements
4. Check blockchain transaction status

### Issue: Contributor Disputes

**Resolution Process:**
1. Open communication with contributor
2. Review code quality objectively
3. Consult community guidelines
4. Escalate to platform arbitration if needed

---

### Issue: Wallet Problems

**Solutions:**
- **Insufficient Gas:** Add XDC for transaction fees
- **Wrong Network:** Ensure you're on XDC Mainnet
- **Connection Issues:** Reconnect wallet or clear cache

### Support Channels

- **Documentation:** [docs.roxonn.com](https://docs.roxonn.com)
- **Discord Community:** Join for real-time support
- **GitHub Issues:** Report bugs or request features
- **Email Support:** [support@roxonn.com](mailto:support@roxonn.com)

---

# Best Practices

## For Successful Project Funding

1. **Start Small:** Begin with modest bounties to test the system  
2. **Clear Requirements:** Write detailed issue descriptions  
3. **Quick Reviews:** Respond promptly to PR submissions  
4. **Fair Compensation:** Research market rates for similar work  
5. **Regular Updates:** Keep your funding pool replenished  

## Community Building

1. **Recognize Contributors:** Publicly acknowledge good work  
2. **Provide Feedback:** Help contributors improve  
3. **Build Relationships:** Engage with active contributors  
4. **Share Success:** Publicize project milestones achieved through contributions

---

# Financial Management

1. **Budget Planning:** Allocate funds for different types of work  
2. **Track Expenses:** Monitor your funding pool balance  
3. **Diversify Tokens:** Consider using multiple token types  
4. **Tax Considerations:** Consult with a tax professional about crypto payments  

---

# Security Considerations

## Protecting Your Funds

1. **Use Hardware Wallets:** For large amounts, use cold storage  
2. **Enable 2FA:** On both GitHub and Roxonn accounts  
3. **Regular Audits:** Review transactions and contributor activity  
4. **Emergency Stop:** Know how to pause payments if needed

---

# Smart Contract Safety

- **Contracts are audited and open source**  
- **Use only verified contract addresses**  
- **Test on Apothem Testnet first**  
- **Start with small transaction amounts**  

# Glossary

- **Pool Manager:** Project maintainer who funds and manages a repository  
- **Bounty:** Reward offered for completing a specific task  
- **Contribution:** Code change submitted via pull request  
- **Reward Pool:** Total funds allocated to a repository  
- **Dispute Period:** Time window for contesting payment decisions  
- **Multi-sig:** Multi-signature wallet requiring multiple approvals

---

# Appendix

## API Reference for Pool Managers

```typescript
// Complete API interface for Pool Managers
interface PoolManagerAPI {
  // Repository Management
  registerRepository(repo: GitHubRepo): Promise<Repository>;
  updateRepositorySettings(id: string, settings: RepoSettings): Promise<void>;
  fundRepository(id: string, amount: string, token: TokenType): Promise<Transaction>;
  
  // Reward Management
  setBounty(issueId: string, amount: string): Promise<void>;
  adjustReward(prId: string, newAmount: string): Promise<void>;
  distributeReward(prId: string, recipients: ContributorSplit[]): Promise<Transaction>;

  // Analytics
  getRepositoryMetrics(id: string): Promise<RepositoryMetrics>;
  getFinancialReport(id: string, timeframe: Timeframe): Promise<FinancialReport>;
  
  // Contributor Management
  blacklistContributor(repoId: string, contributorId: string, reason: string): Promise<void>;
  whitelistContributor(repoId: string, contributorId: string): Promise<void>;
}

---

Quick Reference Commands

```bash
# Check repository balance
curl -X GET https://api.roxonn.com/repos/{repoId}/balance \
  -H "Authorization: Bearer YOUR_TOKEN"

# Add funds to repository
curl -X POST https://api.roxonn.com/repos/{repoId}/fund \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"amount": "100", "token": "XDC"}'

# Get pending payments
curl -X GET https://api.roxonn.com/repos/{repoId}/pending-payments \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

# Need Help?

- **Discord:** Join our community for real-time support  
- **FAQ:** Check our FAQ page for common questions  
- **Email:** [pool-managers@roxonn.com](mailto:pool-managers@roxonn.com)  

---

**Version:** 1.0.0  
**Last Updated:** December 2024  
**Platform Version:** Roxonn v2.1+



