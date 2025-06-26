# Running openSquat as a GitHub Action

This guide explains how to set up openSquat to run automatically as a GitHub Action for continuous security monitoring.

## Overview

openSquat can be automated to run daily scans for domain squatting threats, helping you identify:
- Phishing campaigns targeting your brand
- Domain squatting attempts
- Typo squatting domains
- IDN homograph attacks
- Other brand-related scams

## Quick Start

### 1. Choose Your Workflow

Two workflow files are provided:

- **`opensquat-simple.yml`** - Basic daily scanning with minimal configuration
- **`opensquat-scan.yml`** - Advanced workflow with manual triggers and custom options

### 2. Configure Keywords

Edit the `keywords.txt` file with your target keywords:

```txt
# Add your company/brand keywords here
yourcompany
yourbrand
yourproduct
login
secure
```

### 3. Enable the Workflow

The workflow will automatically run:
- **Daily at 8 AM UTC** (scheduled)
- **When you manually trigger it** (workflow_dispatch)
- **When keywords.txt is updated** (push trigger)

## Workflow Options

### Simple Workflow (`opensquat-simple.yml`)

**Best for:** Basic daily monitoring

**Features:**
- Runs daily at 8 AM UTC
- Uses DNS validation
- Includes phishing database checks
- Outputs results as JSON
- Uploads results as artifacts

**Usage:**
```bash
# Just commit the workflow file and update keywords.txt
git add .github/workflows/opensquat-simple.yml
git commit -m "Add openSquat security scanning"
git push
```

### Advanced Workflow (`opensquat-scan.yml`)

**Best for:** Customizable scanning with manual controls

**Features:**
- Manual trigger with custom parameters
- Configurable confidence levels
- Multiple output formats (txt, json, csv)
- Optional features (DNS, phishing, port checking)
- Automatic issue creation for high-risk findings
- PR comments with scan results

**Manual Trigger Options:**
- **Keywords**: Comma-separated list of keywords to scan
- **Confidence Level**: 0-4 (0=very high, 4=very low)
- **Output Format**: txt, json, or csv
- **Enable DNS**: Enable/disable DNS validation
- **Enable Phishing**: Enable/disable phishing database checks
- **Enable Port Check**: Enable/disable port 80/443 checking

## Configuration

### Environment Variables (Optional)

If you want to send results to Datadog, add this secret:

1. Go to your repository Settings → Secrets and variables → Actions
2. Add a new repository secret:
   - **Name**: `DD_API_KEY`
   - **Value**: Your Datadog API key

### Customizing Scan Parameters

You can modify the workflow files to change:

**Scan Frequency:**
```yaml
schedule:
  - cron: '0 8 * * *'  # Daily at 8 AM UTC
  # Other options:
  # '0 */6 * * *'     # Every 6 hours
  # '0 8 * * 1-5'     # Weekdays only
```

**Default Options:**
```yaml
# In the workflow file, modify the python command:
python opensquat.py -c 1 -o results.json -t json --dns --phishing phishing.txt
```

**Confidence Levels:**
- `0`: Very high (fewer false positives, may miss threats)
- `1`: High (default, good balance)
- `2`: Medium (more results, some false positives)
- `3`: Low (many results, more false positives)
- `4`: Very low (maximum coverage, many false positives)

## Viewing Results

### GitHub Actions Artifacts

1. Go to your repository → Actions tab
2. Click on the latest "openSquat Security Scan" run
3. Scroll down to "Artifacts" section
4. Download `opensquat-results` to get your scan results

### Results Files

- **`results.json`** - Main scan results in JSON format
- **`phishing_results.txt`** - Domains flagged by phishing database
- **`results.txt`** - Plain text results (if using txt format)
- **`results.csv`** - CSV format results (if using csv format)

### Example Results

```json
[
  "yourcompany-login.com",
  "yourbrand-secure.net",
  "yourproduct-login.org"
]
```

## Integration Examples

### 1. Slack Notifications

Add this step to your workflow for Slack notifications:

```yaml
- name: Notify Slack
  if: always()
  uses: 8398a7/action-slack@v3
  with:
    status: ${{ job.status }}
    channel: '#security'
    text: 'openSquat scan completed: ${{ job.status }}'
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

### 2. Email Notifications

Use GitHub's built-in email notifications:
1. Go to your GitHub profile → Settings → Notifications
2. Enable email notifications for "Actions"
3. Choose your preferred email frequency

### 3. SIEM Integration

Download the JSON results and feed them to your SIEM:

```bash
# Example: Download latest results
gh run download --repo your-org/your-repo --name opensquat-results
```

## Troubleshooting

### Common Issues

**Workflow not running:**
- Check that the workflow file is in `.github/workflows/`
- Verify the cron syntax is correct
- Ensure the repository has Actions enabled

**No results found:**
- Check your keywords.txt file
- Try lowering the confidence level
- Verify the tool is working locally first

**Dependency errors:**
- Check that requirements.txt is up to date
- Verify Python version compatibility

### Debug Mode

To run with verbose output, modify the workflow:

```yaml
- name: Run openSquat scan
  run: |
    python opensquat.py -v -o results.json -t json --dns
```

## Security Considerations

1. **API Keys**: Store sensitive keys as GitHub Secrets
2. **Results**: Be careful with scan results in public repositories
3. **Rate Limits**: Be mindful of external API rate limits (VirusTotal, etc.)
4. **Keywords**: Don't commit sensitive keywords to public repos

## Best Practices

1. **Start Simple**: Use the simple workflow first, then customize
2. **Monitor Results**: Check results regularly and adjust parameters
3. **Update Keywords**: Keep your keywords.txt updated with new threats
4. **Review Alerts**: Investigate high-risk findings promptly
5. **Document Findings**: Keep records of confirmed threats

## Support

- **Issues**: Open a GitHub issue for workflow problems
- **Documentation**: Check the main openSquat README.md
- **Community**: Join discussions in the openSquat repository

## Example Workflow Timeline

```
8:00 AM UTC - Workflow starts
8:01 AM UTC - Python environment setup
8:02 AM UTC - Dependencies installed
8:03 AM UTC - openSquat scan begins
8:05 AM UTC - Scan completes, results uploaded
8:06 AM UTC - Summary displayed
8:07 AM UTC - Workflow ends
```

Total runtime: ~7 minutes (varies based on keywords and options) 