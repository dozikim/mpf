# =============================================================================
# MPF Guided Analysis Advisor
# After every action, tells the user exactly what to do next — with reasoning.
# Like having a senior pentester watching over your shoulder.
# =============================================================================

module MPF
  module CLI
    class GuidedAdvisor
      # OWASP category → recommended follow-up exploit/payload
      OWASP_FOLLOWUP = {
        "M1"  => { exploits: %w[ipc_bypass intent_hijacking broadcast_receiver_exploit deeplink_injection],
                   payloads: %w[broadcast_spoofer data_exfiltration],
                   reason:   "Platform misuse detected. Exported components are your primary attack surface." },
        "M2"  => { exploits: %w[clipboard_hijack],
                   payloads: %w[credential_stealer data_exfiltration clipboard_spy screen_capture],
                   reason:   "Insecure storage confirmed. Focus on extracting credentials and sensitive files." },
        "M3"  => { exploits: [],
                   payloads: %w[data_exfiltration reverse_shell],
                   reason:   "Cleartext comms detected. Stage reverse_shell or intercept traffic with a proxy." },
        "M4"  => { exploits: %w[fragment_injection ipc_bypass],
                   payloads: %w[credential_stealer token_extractor keylogger],
                   reason:   "Weak auth detected. Hardcoded credentials or token theft is likely viable." },
        "M5"  => { exploits: [],
                   payloads: %w[token_extractor credential_stealer],
                   reason:   "Weak crypto found. Encrypted data may be decryptable with extracted key." },
        "M6"  => { exploits: %w[ipc_bypass intent_hijacking],
                   payloads: %w[data_exfiltration],
                   reason:   "Authorization flaw. Try accessing protected endpoints via exported components." },
        "M7"  => { exploits: %w[sql_injection webview_rce deeplink_injection],
                   payloads: %w[reverse_shell data_exfiltration],
                   reason:   "Code quality issue. SQL injection or WebView RCE are the most critical next steps." },
        "M8"  => { exploits: [],
                   payloads: %w[persistence_agent],
                   reason:   "Tampering possible. App can be modified — stage persistence_agent for backdoor." },
        "M9"  => { exploits: [],
                   payloads: %w[token_extractor credential_stealer],
                   reason:   "Reverse engineering risk. Extract business logic, hardcoded keys and secrets." },
        "M10" => { exploits: [],
                   payloads: %w[data_exfiltration],
                   reason:   "Debug/test functionality exposed. Look for backdoor endpoints or test credentials." },
      }.freeze

      # Severity → urgency message
      SEVERITY_URGENCY = {
        "CRITICAL" => "\e[31m[!!!] CRITICAL RISK\e[0m — Exploit this immediately. Full compromise is likely.",
        "HIGH"     => "\e[33m[!!]  HIGH RISK\e[0m — Strong attack surface. Should be exploited in this session.",
        "MEDIUM"   => "\e[33m[!]   MEDIUM RISK\e[0m — Worth investigating. Combine with other findings for full chain.",
        "LOW"      => "\e[32m[~]   LOW RISK\e[0m — Informational. Note and continue to higher-severity targets.",
      }.freeze

      def initialize(framework)
        @framework = framework
        @session   = framework.session
        @step_num  = 0
      end

      # -----------------------------------------------------------------------
      # Called after analysis completes — gives a full guided roadmap
      # -----------------------------------------------------------------------
      def after_analysis(result)
        return unless result && result[:findings]

        findings = result[:findings]
        chains   = result[:chains] || []
        owasp    = result[:owasp]  || {}

        print_header("GUIDED ANALYSIS — NEXT STEPS")

        # Step 1: Risk summary
        sev_counts = findings.group_by { |f| f[:severity] }.transform_values(&:count)
        puts "\n\e[35m  ◆ RISK SUMMARY\e[0m"
        %w[CRITICAL HIGH MEDIUM LOW].each do |s|
          n = sev_counts[s] || 0
          next if n.zero?
          bar = '█' * [n * 3, 30].min
          puts "    #{SEVERITY_URGENCY[s]}"
          puts "    #{s.ljust(9)} #{bar} (#{n} finding#{n > 1 ? 's' : ''})"
        end

        # Step 2: Attack chains (highest priority)
        unless chains.empty?
          puts "\n\e[35m  ◆ ATTACK CHAINS DETECTED — FOLLOW THESE FIRST\e[0m"
          chains.each_with_index do |chain, i|
            puts "\n    \e[36m[Chain #{i+1}]\e[0m #{chain[:name]}"
            puts "    Confidence: \e[32m#{chain[:confidence]}%\e[0m  |  Path: #{chain[:owasp_chain]&.join(' → ')}"
            puts "    \e[33mSteps:\e[0m"
            (chain[:steps] || []).each_with_index do |step, si|
              puts "      #{si+1}. #{step}"
            end
          end
        end

        # Step 3: Prioritised next commands
        puts "\n\e[35m  ◆ PRIORITISED NEXT COMMANDS (copy-paste ready)\e[0m"
        step = 1

        # Find worst findings and suggest exact commands
        crits = findings.select { |f| f[:severity] == "CRITICAL" }
        highs = findings.select { |f| f[:severity] == "HIGH" }

        suggested = (crits + highs).first(5)
        suggested.each do |f|
          owasp_cats = f[:owasp].to_s.split(",").map(&:strip)
          owasp_cats.each do |cat|
            followup = OWASP_FOLLOWUP[cat]
            next unless followup

            followup[:exploits].first(1).each do |exploit|
              path = "exploits/android/#{exploit}"
              next unless @framework.modules.key?(path)
              puts "\n    \e[36mStep #{step}:\e[0m Exploit '#{f[:title]}' (#{cat})"
              puts "    \e[33mReason:\e[0m #{followup[:reason]}"
              puts "    \e[32m→ use #{path}\e[0m"
              puts "    \e[32m→ set TARGET <your_apk.apk>\e[0m"
              puts "    \e[32m→ run\e[0m"
              step += 1
              break
            end
          end
          break if step > 4
        end

        # Step 4: Payload recommendation
        puts "\n    \e[36mStep #{step}:\e[0m Stage best payload for data harvest"
        best_payload = recommend_payload(findings)
        puts "    \e[32m→ use payloads/android/#{best_payload}\e[0m"
        puts "    \e[32m→ set TARGET <your_apk.apk>\e[0m"
        puts "    \e[32m→ run\e[0m"
        step += 1

        # Step 5: Report
        puts "\n    \e[36mStep #{step}:\e[0m Generate compliance report"
        puts "    \e[32m→ report generate\e[0m"

        # Step 6: Automation hint
        puts "\n\e[35m  ◆ AUTOMATION HINT\e[0m"
        puts "    Run all recommended modules automatically with:"
        puts "    \e[32m→ autorun <your_apk.apk>\e[0m"
        puts "    Or build a custom workflow:"
        puts "    \e[32m→ workflow run full_scan TARGET=<your_apk.apk>\e[0m"
        puts ""
      end

      # -----------------------------------------------------------------------
      # Called after a single exploit runs — tells user what to do next
      # -----------------------------------------------------------------------
      def after_exploit(mod_meta, result)
        return unless mod_meta

        print_header("NEXT STEPS AFTER #{mod_meta[:name].upcase}")

        findings_count = result[:findings].to_i rescue 0
        owasp_cats = mod_meta[:owasp].to_s.split(",").map(&:strip)

        if findings_count > 0
          puts "\n  \e[32m[+]\e[0m \e[32m#{findings_count} finding(s) confirmed.\e[0m #{SEVERITY_URGENCY[mod_meta[:severity]]}"

          # Recommend compatible payloads
          puts "\n  \e[35m◆ RECOMMENDED PAYLOADS\e[0m (compatible with #{mod_meta[:name]}):"
          compat = compatible_payloads(mod_meta[:name])
          compat.first(3).each_with_index do |p, i|
            pmeta = @framework.modules["payloads/android/#{p}"]
            next unless pmeta
            puts "    #{i+1}. \e[36mpayloads/android/#{p}\e[0m"
            puts "       #{pmeta[:description]}"
            puts "       \e[32m→ set PAYLOAD payloads/android/#{p} && run\e[0m"
          end

          # Chain suggestion
          owasp_cats.each do |cat|
            followup = OWASP_FOLLOWUP[cat]
            next unless followup && followup[:exploits].any?
            puts "\n  \e[35m◆ CHAIN THIS FINDING — try next:\e[0m"
            followup[:exploits].reject { |e| e == mod_meta[:name] }.first(2).each do |e|
              puts "    \e[32m→ use exploits/android/#{e}\e[0m  (#{cat}: #{followup[:reason]})"
            end
          end
        else
          puts "\n  \e[33m[~]\e[0m No findings for this module on the current target."
          puts "  \e[35m◆ TRY INSTEAD:\e[0m"
          owasp_cats.each do |cat|
            alts = OWASP_FOLLOWUP[cat]
            next unless alts
            alts[:exploits].reject { |e| e == mod_meta[:name] }.first(2).each do |e|
              puts "    \e[32m→ use exploits/android/#{e}\e[0m"
            end
          end
        end

        puts "\n  \e[35m◆ ALWAYS RUN AFTER ANY EXPLOIT:\e[0m"
        puts "    \e[32m→ report generate\e[0m  (save evidence before next step)"
        puts ""
      end

      # -----------------------------------------------------------------------
      # Called after 'use <module>' — contextual module hints
      # -----------------------------------------------------------------------
      def after_module_loaded(mod_meta)
        return unless mod_meta

        owasp_cats = mod_meta[:owasp].to_s.split(",").map(&:strip)
        puts "\n\e[35m  ◆ QUICK GUIDE — #{mod_meta[:name].upcase}\e[0m"
        puts "  #{SEVERITY_URGENCY[mod_meta[:severity]] || ''}"
        puts ""
        puts "  \e[35mRequired steps:\e[0m"
        puts "    1. \e[32mset TARGET /path/to/target.apk\e[0m"

        if mod_meta[:type] == :exploit
          puts "    2. \e[32mshow options\e[0m  (verify all required params)"
          puts "    3. \e[32mrun\e[0m"
          puts "    4. After run → \e[32mreport generate\e[0m"

          compat = compatible_payloads(mod_meta[:name])
          unless compat.empty?
            puts ""
            puts "  \e[35mOptional — pair with payload:\e[0m"
            compat.first(2).each do |p|
              puts "    → \e[32mset PAYLOAD payloads/android/#{p}\e[0m"
            end
          end
        elsif mod_meta[:type] == :payload
          puts "    2. \e[32mrun\e[0m  (simulation mode — no real execution)"
        else
          puts "    2. \e[32mrun\e[0m"
        end

        puts ""
        owasp_cats.each do |cat|
          info = OWASP_FOLLOWUP[cat]
          next unless info
          puts "  \e[35mOWASP #{cat} attack chain context:\e[0m"
          puts "  #{info[:reason]}"
          puts ""
        end
      end

      private

      def print_header(title)
        bar = '─' * (title.length + 4)
        puts "\n\e[36m  ┌#{bar}┐\e[0m"
        puts "\e[36m  │  #{title}  │\e[0m"
        puts "\e[36m  └#{bar}┘\e[0m"
      end

      def recommend_payload(findings)
        severities = findings.map { |f| f[:severity] }
        return "reverse_shell"    if severities.include?("CRITICAL")
        return "credential_stealer" if findings.any? { |f| f[:owasp].to_s.include?("M2") }
        return "data_exfiltration" if findings.any? { |f| f[:owasp].to_s.include?("M1") }
        "data_exfiltration"
      end

      def compatible_payloads(exploit_name)
        compat = {
          "sql_injection"              => %w[data_exfiltration credential_stealer],
          "webview_rce"                => %w[reverse_shell screen_capture token_extractor],
          "ipc_bypass"                 => %w[persistence_agent token_extractor data_exfiltration],
          "intent_hijacking"           => %w[broadcast_spoofer gps_tracker clipboard_spy],
          "deeplink_injection"         => %w[data_exfiltration log_injector],
          "broadcast_receiver_exploit" => %w[broadcast_spoofer persistence_agent],
          "clipboard_hijack"           => %w[credential_stealer clipboard_spy],
          "fragment_injection"         => %w[keylogger credential_stealer],
          "tapjacking"                 => %w[credential_stealer screen_capture],
        }
        compat[exploit_name] || %w[data_exfiltration]
      end
    end
  end
end
