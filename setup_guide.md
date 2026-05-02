# Setup Guide — Splunk SOC Home Lab

## Requirements

- Windows 10/11 (64-bit)
- Minimum 4GB RAM (8GB recommended)
- 20GB free disk space
- Free Splunk account

## Step 1 — Install Splunk Enterprise

1. Go to https://www.splunk.com/en_us/download/splunk-enterprise.html
2. Register a free account
3. Download the `.msi` installer for Windows
4. Run the installer, accept the license
5. Create your admin username and password
6. Open your browser: http://localhost:8000

> Free tier allows up to 500MB/day of log ingestion — enough for a home lab.

## Step 2 — Connect Windows Event Logs

1. In Splunk Web, go to **Settings → Data inputs**
2. Click **Local Event Log monitoring → Add new**
3. Select the following logs:
   - `Security`
   - `System`
   - `Application`
4. Set Index to `default`
5. Click **Next → Review → Submit**

## Step 3 — Verify Data is Flowing

Run this search in Splunk:

```spl
index=* | stats count by sourcetype | sort -count
```

You should see:
```
WinEventLog:Security    ~30000+
WinEventLog:System      ~9000+
WinEventLog:Application ~4000+
```

## Step 4 — Run Detection Rules

Copy any `.spl` file from the `detection-rules/` folder and paste into the Splunk search bar.

Set the time range to **All time** for best results.
