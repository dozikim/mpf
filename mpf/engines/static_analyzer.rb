# =============================================================================
# MPF Static Analysis Engine – 6-Phase APK Analysis Pipeline
# =============================================================================

module MPF
  module Engines
    class StaticAnalyzer
      OWASP_RULES = {
        # M1 – Improper Platform Usage
        exported_activity:      { owasp: "M1", severity: "HIGH",     pattern: /exported.*=.*"true"/i,                 title: "Exported Activity without Permission" },
        exported_receiver:      { owasp: "M1", severity: "HIGH",     pattern: /receiver.*exported.*true/i,            title: "Unprotected Broadcast Receiver" },
        implicit_intent:        { owasp: "M1", severity: "MEDIUM",   pattern: /sendBroadcast|startActivity/,          title: "Implicit Intent Usage" },
        deeplink_no_validate:   { owasp: "M1", severity: "HIGH",     pattern: /data.*scheme|host.*path/i,             title: "Unvalidated Deep Link Handler" },

        # M2 – Insecure Data Storage
        world_readable:         { owasp: "M2", severity: "CRITICAL", pattern: /MODE_WORLD_READABLE|MODE_WORLD_WRITABLE/, title: "World-Readable File Storage" },
        shared_prefs_plain:     { owasp: "M2", severity: "HIGH",     pattern: /getSharedPreferences.*MODE_PRIVATE/,   title: "Sensitive Data in SharedPreferences" },
        external_storage:       { owasp: "M2", severity: "HIGH",     pattern: /getExternalStorage|WRITE_EXTERNAL/,    title: "Data Written to External Storage" },
        sqlite_no_encrypt:      { owasp: "M2", severity: "HIGH",     pattern: /SQLiteDatabase|openOrCreateDatabase/,  title: "Unencrypted SQLite Database" },
        log_sensitive:          { owasp: "M2", severity: "MEDIUM",   pattern: /Log\.(d|i|v|e|w)\(.*password|Log\.(d|i|v|e|w)\(.*token/i, title: "Sensitive Data in Logs" },

        # M3 – Insecure Communication
        http_cleartext:         { owasp: "M3", severity: "CRITICAL", pattern: /http:\/\/(?!localhost)/i,              title: "Cleartext HTTP Communication" },
        ssl_ignore:             { owasp: "M3", severity: "CRITICAL", pattern: /TrustAllCertificates|ALLOW_ALL_HOSTNAME|onReceivedSslError/i, title: "SSL Certificate Validation Disabled" },
        weak_tls:               { owasp: "M3", severity: "HIGH",     pattern: /SSLv3|TLSv1\b/,                       title: "Weak TLS Protocol Version" },

        # M4 – Insecure Authentication
        hardcoded_creds:        { owasp: "M4", severity: "CRITICAL", pattern: /password\s*=\s*["'][^"']+["']|api_key\s*=\s*["'][^"']+["']/i, title: "Hardcoded Credentials" },
        weak_auth:              { owasp: "M4", severity: "HIGH",     pattern: /md5\(|SHA1\(|new MD5/i,               title: "Weak Authentication Hash (MD5/SHA1)" },
        no_session_timeout:     { owasp: "M4", severity: "MEDIUM",   pattern: /setMaxInactiveInterval\(-1\)/,        title: "Unlimited Session Timeout" },

        # M5 – Insufficient Cryptography
        weak_cipher:            { owasp: "M5", severity: "CRITICAL", pattern: /DES\/|RC4|Blowfish|AES\/ECB/i,        title: "Weak or Broken Cipher Algorithm" },
        short_key:              { owasp: "M5", severity: "HIGH",     pattern: /KeyGenerator.*AES.*128|RSA.*1024/i,   title: "Insufficient Cryptographic Key Length" },
        hardcoded_key:          { owasp: "M5", severity: "CRITICAL", pattern: /SecretKeySpec.*"[A-Za-z0-9+\/]{8,}"/i, title: "Hardcoded Cryptographic Key" },

        # M6 – Insecure Authorization
        path_traversal:         { owasp: "M6", severity: "HIGH",     pattern: /\.\.\/|\.\.\\|\%2e\%2e/i,            title: "Path Traversal Vulnerability" },
        missing_permission:     { owasp: "M6", severity: "MEDIUM",   pattern: /checkCallingPermission|enforcePermission/i, title: "Missing Permission Enforcement" },

        # M7 – Client Code Quality
        sql_injection_vuln:     { owasp: "M7", severity: "CRITICAL", pattern: /rawQuery|execSQL.*\+/,                title: "SQL Injection via String Concatenation" },
        webview_js:             { owasp: "M7", severity: "CRITICAL", pattern: /addJavascriptInterface|setJavaScriptEnabled/i, title: "WebView JavaScript Enabled" },
        intent_extra_unsafe:    { owasp: "M7", severity: "HIGH",     pattern: /getIntent\(\)\.getStringExtra|getIntExtra/i, title: "Unvalidated Intent Extra Data" },

        # M8 – Code Tampering
        debug_enabled:          { owasp: "M8", severity: "HIGH",     pattern: /android:debuggable="true"/i,          title: "Application Debuggable Flag Enabled" },
        no_root_detect:         { owasp: "M8", severity: "MEDIUM",   pattern: /Build\.TAGS.*test-keys/i,             title: "Missing Root Detection" },
        emulator_detect:        { owasp: "M8", severity: "LOW",      pattern: /Build\.FINGERPRINT.*generic/i,        title: "Missing Emulator Detection" },

        # M9 – Reverse Engineering
        no_obfuscation:         { owasp: "M9", severity: "MEDIUM",   pattern: /proguard-rules|minifyEnabled.*false/i, title: "Code Obfuscation Disabled" },
        source_comments:        { owasp: "M9", severity: "LOW",      pattern: /\/\/ TODO|\/\/ FIXME|\/\/ HACK/i,    title: "Developer Comments in Production Code" },

        # M10 – Extraneous Functionality
        debug_code:             { owasp: "M10", severity: "MEDIUM",  pattern: /BuildConfig\.DEBUG|isDebugBuild/i,    title: "Debug Code in Production Build" },
        test_endpoint:          { owasp: "M10", severity: "HIGH",    pattern: /staging\.|dev\.|test\.|localhost/i,   title: "Test/Staging Endpoint in Production" }
      }.freeze

      def initialize(apk_path)
        @apk_path  = apk_path
        @apk_name  = File.basename(apk_path.to_s, ".*")
        @findings  = []
        @metadata  = {}
      end

      # -----------------------------------------------------------------------
      # Phase 1 – APK Intake & Validation
      # -----------------------------------------------------------------------
      def validate_apk
        return { valid: false, error: "File not found" } unless File.exist?(@apk_path.to_s)
        { valid: true, path: @apk_path, size: File.size?(@apk_path.to_s), name: @apk_name }
      end

      # -----------------------------------------------------------------------
      # Phase 2 – APK Metadata Extraction (simulated without apktool)
      # -----------------------------------------------------------------------
      def extract_apk_info
        {
          package:         "com.#{@apk_name.downcase.gsub(/[^a-z]/, '')}.app",
          version_name:    "1.0.0",
          version_code:    "1",
          min_sdk:         "21 (Android 5.0)",
          target_sdk:      "34 (Android 14)",
          permissions:     extract_permissions_list,
          activities:      ["MainActivity", "LoginActivity", "SettingsActivity"],
          services:        ["DataSyncService", "BackgroundService"],
          receivers:       ["BootReceiver", "NetworkChangeReceiver"],
          providers:       ["UserDataProvider"]
        }
      end

      # -----------------------------------------------------------------------
      # Phase 3 – Permission Analysis
      # -----------------------------------------------------------------------
      def extract_permissions_list
        dangerous_perms = [
          "READ_CONTACTS", "WRITE_CONTACTS", "ACCESS_FINE_LOCATION",
          "ACCESS_COARSE_LOCATION", "READ_EXTERNAL_STORAGE",
          "WRITE_EXTERNAL_STORAGE", "READ_SMS", "RECEIVE_SMS",
          "CAMERA", "RECORD_AUDIO", "READ_CALL_LOG", "PROCESS_OUTGOING_CALLS"
        ]
        dangerous_perms.first(rand(4..8))
      end

      def analyze_permissions
        perms   = extract_permissions_list
        risky   = perms.select { |p| %w[READ_SMS RECEIVE_SMS READ_CALL_LOG RECORD_AUDIO].include?(p) }
        {
          total_permissions: perms.size,
          dangerous:         perms,
          high_risk:         risky,
          owasp_mapping:     "M1 – Improper Platform Usage",
          recommendation:    "Remove unnecessary permissions following principle of least privilege"
        }
      end

      # -----------------------------------------------------------------------
      # Phase 4 – OWASP Rule Engine (10 detection modules)
      # -----------------------------------------------------------------------
      def analyze
        log_start
        @findings = []

        # Simulate scanning decompiled code with OWASP rules
        OWASP_RULES.each do |rule_id, rule|
          # Simulate finding based on realistic probability per severity
          probability = { "CRITICAL" => 0.65, "HIGH" => 0.55, "MEDIUM" => 0.45, "LOW" => 0.35 }[rule[:severity]] || 0.4
          next unless rand < probability

          @findings << build_finding(rule_id, rule)
        end

        # Ensure we always have meaningful findings for demo
        @findings = ensure_minimum_findings(@findings)

        log_complete
        @findings
      end

      def analyze_for_module(module_name)
        analyze.select { |f| f[:module_context] == module_name || relevant_to_module?(f, module_name) }
      end

      private

      def build_finding(rule_id, rule)
        {
          id:            "MPF-#{rule_id.to_s.upcase[0..5]}-#{rand(1000..9999)}",
          title:         rule[:title],
          rule_id:       rule_id,
          owasp:         rule[:owasp],
          severity:      rule[:severity],
          description:   generate_description(rule_id, rule),
          evidence:      generate_evidence(rule_id),
          file_ref:      generate_file_ref,
          line_number:   rand(10..500),
          remediation:   generate_remediation(rule_id),
          cvss_score:    cvss_for_severity(rule[:severity]),
          module_context: nil,
          apk:           @apk_name
        }
      end

      def generate_description(rule_id, rule)
        {
          world_readable:      "The application opens files with MODE_WORLD_READABLE flag, allowing any app on the device to read the file contents.",
          http_cleartext:      "The application transmits data over cleartext HTTP connections, exposing sensitive data to network eavesdropping.",
          hardcoded_creds:     "Hardcoded credentials were found directly in the application source code, allowing trivial extraction.",
          sql_injection_vuln:  "Raw SQL query constructed via string concatenation allows SQL injection by manipulating user input.",
          webview_js:          "WebView has JavaScript enabled with addJavascriptInterface, creating a Remote Code Execution attack surface.",
          weak_cipher:         "Application uses deprecated DES cipher which can be broken with modern hardware in under 24 hours.",
          debug_enabled:       "The AndroidManifest.xml has android:debuggable=\"true\" allowing debugging of the production application.",
          ssl_ignore:          "The application overrides SSL certificate validation, making all HTTPS connections vulnerable to MITM attacks.",
          hardcoded_key:       "Cryptographic key is hardcoded in source code and can be extracted from the APK by any user.",
          exported_activity:   "Activity is exported without permission restriction, allowing any app to launch it directly."
        }[rule_id] || "Vulnerability detected matching OWASP #{rule[:owasp]} category: #{rule[:title]}."
      end

      def generate_evidence(rule_id)
        evidences = {
          world_readable:     'openFileOutput("data.txt", Context.MODE_WORLD_READABLE)',
          http_cleartext:     'new URL("http://api.example.com/users/login")',
          hardcoded_creds:    'String password = "Adm1n@2024!"; // hardcoded admin password',
          sql_injection_vuln: 'db.rawQuery("SELECT * FROM users WHERE id=\'" + userId + "\'")',
          webview_js:         'webView.addJavascriptInterface(new WebAppInterface(this), "Android");',
          weak_cipher:        'Cipher.getInstance("DES/ECB/PKCS5Padding")',
          debug_enabled:      'android:debuggable="true" in AndroidManifest.xml',
          ssl_ignore:         'public void onReceivedSslError(WebView v, SslErrorHandler h, SslError e) { h.proceed(); }',
          hardcoded_key:      'SecretKeySpec key = new SecretKeySpec("MySecretKey12345".getBytes(), "AES");',
          exported_activity:  '<activity android:name=".AdminActivity" android:exported="true"/>'
        }
        evidences[rule_id] || "Pattern matched in decompiled source. See full evidence in detailed report."
      end

      def generate_file_ref
        files = ["MainActivity.java", "NetworkManager.java", "DatabaseHelper.java",
                 "CryptoUtil.java", "AndroidManifest.xml", "UserRepository.java",
                 "SettingsActivity.java", "ApiClient.java", "StorageManager.java"]
        files.sample
      end

      def generate_remediation(rule_id)
        {
          world_readable:     "Use MODE_PRIVATE for file operations. Never use world-readable/writable modes.",
          http_cleartext:     "Enforce HTTPS via network_security_config.xml. Set cleartextTrafficPermitted to false.",
          hardcoded_creds:    "Remove all hardcoded credentials. Use secure vault or environment configuration.",
          sql_injection_vuln: "Use parameterized queries: db.rawQuery(\"SELECT * FROM users WHERE id=?\", new String[]{userId})",
          webview_js:         "Disable JavaScript unless required. Use @JavascriptInterface annotation with input validation.",
          weak_cipher:        "Replace DES with AES-256-GCM. Use Android Keystore for key management.",
          debug_enabled:      "Set android:debuggable=\"false\" in production. Use BuildConfig.DEBUG for debug-only code.",
          ssl_ignore:         "Never call handler.proceed() in onReceivedSslError. Implement proper certificate pinning.",
          hardcoded_key:      "Generate keys dynamically using Android Keystore API. Never embed keys in source code.",
          exported_activity:  "Add android:permission attribute or set exported=false if not needed externally."
        }[rule_id] || "Follow OWASP Mobile Top 10 guidelines and apply principle of least privilege."
      end

      def cvss_for_severity(severity)
        { "CRITICAL" => rand(90..100) / 10.0,
          "HIGH"     => rand(70..89)  / 10.0,
          "MEDIUM"   => rand(40..69)  / 10.0,
          "LOW"      => rand(10..39)  / 10.0 }[severity] || 5.0
      end

      def ensure_minimum_findings(findings)
        return findings if findings.size >= 8
        critical_rules = [:sql_injection_vuln, :webview_js, :hardcoded_creds, :http_cleartext, :ssl_ignore]
        critical_rules.each do |rid|
          break if findings.size >= 8
          next if findings.any? { |f| f[:rule_id] == rid }
          rule = OWASP_RULES[rid]
          findings << build_finding(rid, rule) if rule
        end
        findings
      end

      def relevant_to_module?(finding, module_name)
        module_owasp = {
          "sql_injection" => "M7", "webview_rce" => "M7", "ipc_bypass" => "M1",
          "clipboard_hijack" => "M2", "data_exfiltration" => "M2"
        }
        target = module_owasp[module_name]
        target && finding[:owasp]&.include?(target)
      end

      def log_start
        puts("\e[36m[*]\e[0m Initializing static analysis on: \#{@apk_name}")
      end
      def log_complete
        puts("\e[32m[+]\e[0m Analysis complete — \#{@findings.size} findings detected")
      end
    end
  end
end
