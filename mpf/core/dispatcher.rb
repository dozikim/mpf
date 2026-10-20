# =============================================================================
# MPF Core Dispatcher – Module Execution Orchestration
# =============================================================================

require_relative '../engines/static_analyzer'
require_relative '../engines/owasp_engine'
require_relative '../engines/chain_reasoner'
require_relative '../reporters/json_reporter'
require_relative '../reporters/html_reporter'

module MPF
  module Core
    class Dispatcher
      def initialize(framework)
        @framework = framework
        @session   = framework.session
      end

      def execute_module(mod_meta, options = {})
        return error("No target APK specified") unless options[:TARGET] || @session.get_option(:TARGET)

        target  = options[:TARGET] || @session.get_option(:TARGET)
        return error("Target APK not found: #{target}") unless File.exist?(target.to_s)

        type    = mod_meta[:type]

        log_info("Dispatching #{type} module: #{mod_meta[:name]}")
        log_info("Target: #{target}")

        case type
        when :auxiliary then run_auxiliary(mod_meta, target)
        when :exploit   then run_exploit(mod_meta, target, options)
        when :payload   then run_payload(mod_meta, target, options)
        else error("Unknown module type: #{type}")
        end
      end

      def run_full_analysis(apk_path)
        unless apk_path && File.exist?(apk_path.to_s)
          empty_report = Engines::OWASPEngine.new([]).generate_compliance_report
          return {
            findings: [],
            owasp:    empty_report,
            chains:   [],
            session:  @session.summary,
            reports:  {},
            error:    "Target APK not found: #{apk_path}"
          }
        end

        log_info("Starting full analysis pipeline on: #{apk_path}")

        # Phase 1 – Static Analysis
        log_phase("Phase 1: Static Analysis")
        analyzer  = Engines::StaticAnalyzer.new(apk_path)
        raw_findings = analyzer.analyze

        # Phase 2 – OWASP Mapping
        log_phase("Phase 2: OWASP Compliance Engine")
        owasp_engine = Engines::OWASPEngine.new(raw_findings)
        owasp_report = owasp_engine.generate_compliance_report

        # Phase 3 – Attack Chain Reasoning
        log_phase("Phase 3: Attack Chain Reasoning")
        reasoner = Engines::ChainReasoner.new(raw_findings)
        chains   = reasoner.generate_chains

        # Phase 4 – Session Results
        raw_findings.each { |f| @session.add_result(f) }

        # Phase 5 – Report Generation (actually write the files; previously
        # the reporters were constructed but generate() was never called, so
        # `analyze` silently produced no report files at all)
        log_phase("Phase 4: Report Generation")
        output_dir = @session.get_option(:OUTPUT) || "./reports"
        json_reporter = Reporters::JSONReporter.new(owasp_report, chains, @session)
        html_reporter = Reporters::HTMLReporter.new(owasp_report, chains, @session)
        json_path = json_reporter.generate(File.join(output_dir, "mpf_report.json"))
        html_path = html_reporter.generate(File.join(output_dir, "mpf_report.html"))

        {
          findings:    raw_findings,
          owasp:       owasp_report,
          chains:      chains,
          session:     @session.summary,
          reports:     { json: json_path, html: html_path }
        }
      end

      private

      def run_auxiliary(mod_meta, target)
        log_info("Running auxiliary: #{mod_meta[:name]}")
        analyzer = Engines::StaticAnalyzer.new(target)
        data = case mod_meta[:name]
               when "apk_info_scanner"    then analyzer.extract_apk_info
               when "permission_analyzer" then analyzer.analyze_permissions
               end
        # Normalize the return shape so callers (commander summary line,
        # automation) always see :status/:findings — the raw analyzer hashes
        # have neither, which printed a blank "Status:" in the REPL.
        return { status: "completed", module: mod_meta[:name], target: target, findings: 0, data: data } if data

        { status: "ok", module: mod_meta[:name], target: target, findings: 0 }
      end

      def run_exploit(mod_meta, target, options)
        log_info("Running exploit: #{mod_meta[:name]}")
        log_info("\e[33m[SAFE MODE] Evidence-only — no persistent changes\e[0m")
        analyzer = Engines::StaticAnalyzer.new(target)
        findings = analyzer.analyze_for_module(mod_meta[:name])
        findings.each { |f| @session.add_result(f) }
        { status: "completed", exploit: mod_meta[:name], findings: findings.size, evidence: findings }
      end

      def run_payload(mod_meta, target, options)
        log_info("Staging payload: #{mod_meta[:name]}")
        log_info("\e[33m[SAFE MODE] Simulation only — no execution on device\e[0m")
        { status: "staged", payload: mod_meta[:name], target: target, simulated: true }
      end

      def log_info(msg)
        puts("\e[36m[*]\e[0m #{msg}")
      end
      def log_phase(msg)
        puts("\n\e[35m[PHASE]\e[0m #{msg}")
      end
      def error(msg)
        { status: "error", message: msg }
      end
    end
  end
end
