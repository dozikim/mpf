# =============================================================================
# MPF Attack Chain Reasoning Engine – Multi-Step Vulnerability Correlation
# =============================================================================

module MPF
  module Engines
    class ChainReasoner
      # Define known attack chain templates
      CHAIN_TEMPLATES = [
        {
          id:          "CHAIN-001",
          name:        "Data Exfiltration via Insecure Storage",
          description: "Attacker reads plaintext credentials from SharedPreferences, bypasses authentication, then exfiltrates data via cleartext HTTP.",
          owasp_chain: ["M2", "M4", "M3"],
          steps:       ["Locate sensitive data in SharedPreferences", "Extract credentials from plaintext storage", "Bypass authentication using stolen credentials", "Exfiltrate data via HTTP endpoint"],
          severity:    "CRITICAL",
          trigger_rules: [:shared_prefs_plain, :hardcoded_creds, :http_cleartext]
        },
        {
          id:          "CHAIN-002",
          name:        "WebView RCE to Account Takeover",
          description: "Attacker injects JavaScript via WebView, uses addJavascriptInterface to call native methods, then steals OAuth tokens.",
          owasp_chain: ["M7", "M1", "M4"],
          steps:       ["Identify WebView with JavaScript enabled", "Inject malicious JavaScript payload", "Invoke native Android methods via bridge interface", "Extract OAuth token from app storage"],
          severity:    "CRITICAL",
          trigger_rules: [:webview_js, :intent_extra_unsafe, :hardcoded_creds]
        },
        {
          id:          "CHAIN-003",
          name:        "IPC Bypass to Privilege Escalation",
          description: "Malicious app exploits exported Activity/Service to trigger privileged operations without proper authorization.",
          owasp_chain: ["M1", "M6", "M4"],
          steps:       ["Discover exported components via manifest parsing", "Launch exported Activity from malicious app", "Trigger privileged operation without authentication", "Gain unauthorized access to sensitive functionality"],
          severity:    "HIGH",
          trigger_rules: [:exported_activity, :exported_receiver, :missing_permission]
        },
        {
          id:          "CHAIN-004",
          name:        "MITM Attack via SSL Bypass",
          description: "Attacker performs Man-in-the-Middle attack by exploiting disabled SSL validation and cleartext traffic.",
          owasp_chain: ["M3", "M5"],
          steps:       ["Set up network proxy on same network", "Exploit disabled SSL certificate validation", "Intercept and decrypt application traffic", "Steal session tokens and credentials in transit"],
          severity:    "CRITICAL",
          trigger_rules: [:ssl_ignore, :http_cleartext, :weak_tls]
        },
        {
          id:          "CHAIN-005",
          name:        "SQL Injection to Database Dump",
          description: "SQL injection via ContentProvider allows attacker to dump entire application database.",
          owasp_chain: ["M7", "M2"],
          steps:       ["Identify vulnerable ContentProvider query", "Craft SQL injection payload", "Execute UNION SELECT to enumerate tables", "Extract all sensitive data from database"],
          severity:    "CRITICAL",
          trigger_rules: [:sql_injection_vuln, :sqlite_no_encrypt]
        }
      ].freeze

      def initialize(findings)
        @findings = findings
        @detected_rules = findings.map { |f| f[:rule_id] }.compact
      end

      def generate_chains
        active_chains = []

        CHAIN_TEMPLATES.each do |template|
          # Check if at least 2 trigger rules are present in findings
          matched = template[:trigger_rules].count { |r| @detected_rules.include?(r) }
          next if matched < 1

          confidence = (matched.to_f / template[:trigger_rules].size * 100).round
          chain = template.dup
          chain[:confidence]     = confidence
          chain[:matched_rules]  = template[:trigger_rules].select { |r| @detected_rules.include?(r) }
          chain[:missing_rules]  = template[:trigger_rules].reject { |r| @detected_rules.include?(r) }
          chain[:exploitability] = exploitability(confidence, template[:severity])
          active_chains << chain
        end

        active_chains.sort_by { |c| -c[:confidence] }
      end

      private

      def exploitability(confidence, severity)
        base = { "CRITICAL" => 9, "HIGH" => 7, "MEDIUM" => 5, "LOW" => 3 }[severity] || 5
        adjusted = (base * confidence / 100.0).round(1)
        { score: adjusted, label: adjusted >= 7 ? "High" : adjusted >= 4 ? "Medium" : "Low" }
      end
    end
  end
end
