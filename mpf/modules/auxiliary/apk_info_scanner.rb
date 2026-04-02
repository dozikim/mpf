# =============================================================================
# MPF Auxiliary Module: apk_info_scanner
# OWASP: M10 | Type: Intelligence Gathering
# Framework Version: 2.0.0
# =============================================================================

module MPF
  module Modules
    module Auxiliary
      class <built-in method capitalize of str object at 0x7ea5abc43fb0>
        NAME        = "apk_info_scanner".freeze
        OWASP       = "M10".freeze
        DESCRIPTION = "Extracts comprehensive metadata, package structure, and manifest info from APK files.".freeze

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
          log "[+] #apk_info_scanner complete."
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
