# MPF Usage Guide

## Installation

```bash
# 1. Ensure Ruby 2.7+ is installed
ruby --version

# 2. Install optional dependencies (apktool, adb for full dynamic analysis)
# Ubuntu/Debian:
sudo apt install apktool adb

# 3. Run MPF
ruby mpf.rb
```

## Example Sessions

### Session 1 – Full APK Analysis
```
mpf > analyze /path/to/vulnerable_app.apk
mpf > report generate
```

### Session 2 – Targeted Exploit
```
mpf > use exploits/android/webview_rce
mpf exploit(webview_rce) > set TARGET /path/to/app.apk
mpf exploit(webview_rce) > set PAYLOAD payloads/android/reverse_shell
mpf exploit(webview_rce) > show options
mpf exploit(webview_rce) > run
```

### Session 3 – Auxiliary Recon
```
mpf > use auxiliary/android/apk_info_scanner
mpf auxiliary(apk_info_scanner) > set TARGET /path/to/app.apk
mpf auxiliary(apk_info_scanner) > run
mpf > use auxiliary/android/permission_analyzer
mpf auxiliary(permission_analyzer) > run
```

### Session 4 – Search and Explore
```
mpf > search injection
mpf > search M2
mpf > show all
mpf > show payloads
```

## Report Output

Reports are saved in `./reports/` by default:
- `mpf_report.json` – Machine-readable structured findings
- `mpf_report.html` – Interactive browser-viewable report

To customise output directory:
```
mpf > set OUTPUT /custom/path/reports
```

## Module Development

To create a custom exploit module, create a file in `modules/exploits/`:

```ruby
module MPF
  module Modules
    module Exploits
      class MyCustomExploit
        def metadata
          {
            name:        "my_custom_exploit",
            type:        :exploit,
            owasp:       "M1",
            severity:    "HIGH",
            description: "Description of what this exploit does"
          }
        end

        def options
          {
            TARGET: { required: true, desc: "Target APK path" }
          }
        end

        def run(options = {})
          # Your exploit logic here
          # Always operate in safe/evidence-only mode
          []
        end
      end
    end
  end
end
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `apktool not found` | Install apktool: `sudo apt install apktool` |
| `adb not found` | Install Android platform-tools |
| `Module not found` | Use `search <term>` to find correct module path |
| `No findings` | Ensure TARGET is a valid APK file path |
