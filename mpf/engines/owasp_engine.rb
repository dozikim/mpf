# =============================================================================
# MPF OWASP Compliance Engine – 100% Mobile Top 10 Mapping
#
# Category names/weights and severity weights load from
# mpf/config/owasp_rules.yml when it is present and parseable; otherwise the
# built-in defaults (identical to the file) are used.
# =============================================================================

require 'time'
require 'yaml'

module MPF
  module Engines
    class OWASPEngine
      CONFIG_PATH = File.expand_path('../config/owasp_rules.yml', __dir__)

      BUILT_IN_CATEGORIES = {
        "M1"  => { name: "Improper Platform Usage",     weight: 1.0 },
        "M2"  => { name: "Insecure Data Storage",       weight: 1.0 },
        "M3"  => { name: "Insecure Communication",      weight: 0.9 },
        "M4"  => { name: "Insecure Authentication",     weight: 0.9 },
        "M5"  => { name: "Insufficient Cryptography",   weight: 0.8 },
        "M6"  => { name: "Insecure Authorization",      weight: 0.8 },
        "M7"  => { name: "Client Code Quality",         weight: 0.7 },
        "M8"  => { name: "Code Tampering",              weight: 0.6 },
        "M9"  => { name: "Reverse Engineering",         weight: 0.5 },
        "M10" => { name: "Extraneous Functionality",   weight: 0.4 }
      }.freeze

      BUILT_IN_SEVERITY_WEIGHTS = { "CRITICAL" => 10, "HIGH" => 7, "MEDIUM" => 4, "LOW" => 1 }.freeze

      def self.load_config_section(key)
        return nil unless File.exist?(CONFIG_PATH)
        raw = YAML.safe_load(File.read(CONFIG_PATH))
        raw.is_a?(Hash) ? raw[key] : nil
      rescue StandardError
        nil
      end

      def self.build_categories
        raw = load_config_section('owasp_categories')
        return BUILT_IN_CATEGORIES unless raw.is_a?(Hash) && !raw.empty?
        BUILT_IN_CATEGORIES.each_with_object({}) do |(id, defaults), merged|
          entry = raw[id]
          merged[id] = if entry.is_a?(Hash) && entry['name'] && entry['weight']
                         { name: entry['name'].to_s, weight: entry['weight'].to_f }
                       else
                         defaults
                       end
        end
      end

      def self.build_severity_weights
        raw = load_config_section('severity_weights')
        return BUILT_IN_SEVERITY_WEIGHTS unless raw.is_a?(Hash) && !raw.empty?
        weights = BUILT_IN_SEVERITY_WEIGHTS.dup
        raw.each { |k, v| weights[k.to_s.upcase] = v.to_i if weights.key?(k.to_s.upcase) }
        weights
      end

      OWASP_CATEGORIES = build_categories.freeze
      SEVERITY_WEIGHTS = build_severity_weights.freeze

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
        return 100.0 if scored.empty?
        # Average the per-category weighted risk instead of summing it: the
        # old sum saturated at 0 for any non-trivial real APK (>~14 weighted
        # findings), making every grade F and the score meaningless.
        avg = scored.values.sum { |v| v[:weighted] } / scored.size.to_f
        [(100.0 - (avg * 2)).round(1), 0].max
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
