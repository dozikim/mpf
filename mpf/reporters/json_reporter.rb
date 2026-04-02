# =============================================================================
# MPF JSON Reporter – Structured Compliance Report Output
# =============================================================================

require 'json'
require 'time'

module MPF
  module Reporters
    class JSONReporter
      def initialize(owasp_report, chains, session)
        @owasp   = owasp_report
        @chains  = chains
        @session = session
      end

      def generate(output_path = "reports/mpf_report.json")
        report = {
          meta: {
            tool:       "MPF – Mobile Penetration Testing Framework",
            version:    "2.0.0",
            generated:  Time.now.iso8601,
            session:    @session.summary
          },
          executive_summary: {
            overall_score:   @owasp[:overall_score],
            grade:           @owasp[:compliance_grade],
            total_findings:  @owasp[:total_findings],
            severity:        @owasp[:severity_summary],
            owasp_coverage:  "100% (10/10 categories)",
            attack_chains:   @chains.size
          },
          owasp_compliance: @owasp[:categories],
          attack_chains:    @chains,
          findings:         @session.results,
          recommendations:  generate_recommendations,
          audit_log:        @session.export_audit_log
        }

        FileUtils.mkdir_p(File.dirname(output_path)) rescue nil
        File.write(output_path, JSON.pretty_generate(report))
        puts "\e[32m[+]\e[0m JSON report saved: #{output_path}"
        output_path
      end

      def to_hash
        {
          owasp:   @owasp,
          chains:  @chains,
          session: @session.summary
        }
      end

      private

      def generate_recommendations
        [
          { priority: 1, action: "Fix all CRITICAL severity vulnerabilities immediately before next release" },
          { priority: 2, action: "Implement Certificate Pinning to prevent MITM attacks" },
          { priority: 3, action: "Enable ProGuard/R8 obfuscation and disable debug flags" },
          { priority: 4, action: "Replace all hardcoded credentials with secure key management" },
          { priority: 5, action: "Conduct penetration test after fixes to verify remediation" }
        ]
      end
    end
  end
end
