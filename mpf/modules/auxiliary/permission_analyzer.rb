# =============================================================================
# MPF Auxiliary Module: permission_analyzer
# OWASP: M1, M10 | Type: Intelligence Gathering
# Framework Version: 2.0.0
# =============================================================================

module MPF
  module Modules
    module Auxiliary
      class <built-in method capitalize of str object at 0x7ea5abc43ef0>
        NAME        = "permission_analyzer".freeze
        OWASP       = "M1, M10".freeze
        DESCRIPTION = "Analyses declared permissions and maps overprivileged permissions to OWASP risk categories.".freeze

        def metadata
          {
            name:        NAME,
            type:        :auxiliary,
            platform:    :android,
            owasp:       OWASP,
            description: DESCRIPTION
          }
        end

        def options
          {
            TARGET: { required: true, desc: "Path to target APK file" },
            OUTPUT: { required: false, desc: "Report output path", default: "./reports" }
          }
        end

        def run(options = {})
          require_relative "../../engines/static_analyzer"
          analyzer = MPF::Engines::StaticAnalyzer.new(options[:TARGET])
          result   = NAME == "apk_info_scanner" ? analyzer.extract_apk_info : analyzer.analyze_permissions
          log "[+] #permission_analyzer complete."
          result.each { |k, v| log "    #{k}: #{v}" }
          result
        end

        private
        def log(msg)
          $stdout.puts(msg)
        end
      end
    end
  end
end
