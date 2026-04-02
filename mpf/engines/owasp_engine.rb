# =============================================================================
# MPF OWASP Compliance Engine – 100% Mobile Top 10 Mapping
# =============================================================================

require 'time'

module MPF
  module Engines
    class OWASPEngine
      OWASP_CATEGORIES = {
        "M1"  => { name: "Improper Platform Usage",     weight: 1.0 },
        "M2"  => { name: "Insecure Data Storage",       weight: 1.0 },
        "M3"  => { name: "Insecure Communication",      weight: 0.9 },
        "M4"  => { name: "Insecure Authentication",     weight: 0.9 },
        "M5"  => { name: "Insufficient Cryptography",   weight: 0.8 },
        "M6"  => { name: "Insecure Authorization",      weight: 0.8 },
        "M7"  => { name: "Client Code Quality",         weight: 0.7 },
        "M8"  => { name: "Code Tampering",              weight: 0.6 },
        "M9"  => { name: "Reverse Engineering",         weight: 0.5 },
        "M10" => { name: "Extraneous Functionality",    weight: 0.4 }
      }.freeze

      SEVERITY_WEIGHTS = { "CRITICAL" => 10, "HIGH" => 7, "MEDIUM" => 4, "LOW" => 1 }.freeze

      def initialize(findings)
        @findings   = findings
        @categories = OWASP_CATEGORIES.dup
      end

      def generate_compliance_report
        grouped = group_by_category
        scored  = score_categories(grouped)
        overall = compute_overall_score(scored)

        {
          generated_at:    Time.now.iso8601,
          overall_score:   overall,
          compliance_grade: grade(overall),
          total_findings:  @findings.size,
          categories:      scored,
          severity_summary: severity_summary,
          passed_categories: scored.count { |_, v| v[:risk_level] == "LOW" },
          failed_categories: scored.count { |_, v| v[:risk_level] != "LOW" }
        }
      end

      private

      def group_by_category
        grouped = OWASP_CATEGORIES.keys.each_with_object({}) { |k, h| h[k] = [] }
        @findings.each do |finding|
          categories = finding[:owasp].to_s.split(",").map(&:strip)
          categories.each { |cat| grouped[cat] << finding if grouped[cat] }
        end
        grouped
      end

      def score_categories(grouped)
        grouped.transform_values.with_index do |findings, idx|
          cat_key = OWASP_CATEGORIES.keys[idx]
          raw_score = findings.sum { |f| SEVERITY_WEIGHTS[f[:severity]] || 0 }
          weight = OWASP_CATEGORIES[cat_key][:weight]
          weighted = (raw_score * weight).round(1)

          {
            name:        OWASP_CATEGORIES[cat_key][:name],
            findings:    findings.size,
            raw_score:   raw_score,
            weighted:    weighted,
            risk_level:  risk_level(weighted),
            critical:    findings.count { |f| f[:severity] == "CRITICAL" },
            high:        findings.count { |f| f[:severity] == "HIGH" },
            medium:      findings.count { |f| f[:severity] == "MEDIUM" },
            low:         findings.count { |f| f[:severity] == "LOW" }
          }
        end
      end

      def compute_overall_score(scored)
        total = scored.values.sum { |v| v[:weighted] }
        [(100 - total).round(1), 0].max
      end

      def risk_level(score)
        if    score >= 15 then "CRITICAL"
        elsif score >= 8  then "HIGH"
        elsif score >= 3  then "MEDIUM"
        else                   "LOW"
        end
      end

      def grade(score)
        if    score >= 85 then "A"
        elsif score >= 70 then "B"
        elsif score >= 55 then "C"
        elsif score >= 40 then "D"
        else                   "F"
        end
      end

      def severity_summary
        {
          critical: @findings.count { |f| f[:severity] == "CRITICAL" },
          high:     @findings.count { |f| f[:severity] == "HIGH" },
          medium:   @findings.count { |f| f[:severity] == "MEDIUM" },
          low:      @findings.count { |f| f[:severity] == "LOW" }
        }
      end
    end
  end
end
