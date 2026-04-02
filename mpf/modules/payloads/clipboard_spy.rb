# =============================================================================
# MPF Payload Module: clipboard_spy
# OWASP: M2 | Severity: MEDIUM
# Framework Version: 2.0.0
# =============================================================================
# SIMULATION ONLY — No real execution on device or network
# =============================================================================

module MPF
  module Modules
    module Payloads
      class <built-in method capitalize of str object at 0x7ea5abc43ef0>
        NAME        = "clipboard_spy".freeze
        OWASP       = "M2".freeze
        SEVERITY    = "MEDIUM".freeze
        DESCRIPTION = "Monitors the system clipboard continuously for credentials, tokens and sensitive strings.".freeze
        REMEDIATION = "Clear clipboard after sensitive operations. Avoid storing secrets in clipboard history.".freeze

        def metadata
          {
            name:        NAME,
            type:        :payload,
            platform:    :android,
            owasp:       OWASP,
            severity:    SEVERITY,
            description: DESCRIPTION
          }
        end

        def options
          {
            TARGET: { required: true,  desc: "Target APK or device identifier" },
            LHOST:  { required: false, desc: "Listener host (simulation only)" },
            LPORT:  { required: false, desc: "Listener port (simulation only)", default: "4444" }
          }
        end

        def stage(options = {})
          log "[*] Staging payload : #clipboard_spy"
          log "[*] Target          : #{options[:TARGET]}"
          log "[!] SIMULATION ONLY : No code executed on device."
          log "[*] Payload staged and ready for delivery (simulated)."
          {
            status:    "staged",
            payload:   NAME,
            simulated: true,
            owasp:     OWASP,
            severity:  SEVERITY
          }
        end

        private
        def log(msg)
          $stdout.puts(msg)
        end
      end
    end
  end
end
