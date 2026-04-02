# =============================================================================
# MPF Automation Engine
# autorun  – runs all relevant modules against a target automatically
# workflow – named, saveable sequences of commands
# jobs     – track running/completed automation tasks
# =============================================================================

require 'json'
require 'time'

module MPF
  module Automation
    class Engine
      BUILT_IN_WORKFLOWS = {
        "full_scan" => {
          description: "Run all 9 exploits + 2 auxiliary on TARGET, then generate report",
          steps: [
            { cmd: "auxiliary", mod: "auxiliary/android/apk_info_scanner" },
            { cmd: "auxiliary", mod: "auxiliary/android/permission_analyzer" },
            { cmd: "exploit",   mod: "exploits/android/sql_injection" },
            { cmd: "exploit",   mod: "exploits/android/webview_rce" },
            { cmd: "exploit",   mod: "exploits/android/ipc_bypass" },
            { cmd: "exploit",   mod: "exploits/android/intent_hijacking" },
            { cmd: "exploit",   mod: "exploits/android/deeplink_injection" },
            { cmd: "exploit",   mod: "exploits/android/broadcast_receiver_exploit" },
            { cmd: "exploit",   mod: "exploits/android/clipboard_hijack" },
            { cmd: "exploit",   mod: "exploits/android/fragment_injection" },
            { cmd: "exploit",   mod: "exploits/android/tapjacking" },
            { cmd: "report",    mod: nil },
          ]
        },
        "critical_only" => {
          description: "Run only CRITICAL-severity exploit modules",
          steps: [
            { cmd: "exploit", mod: "exploits/android/sql_injection" },
            { cmd: "exploit", mod: "exploits/android/webview_rce" },
            { cmd: "report",  mod: nil },
          ]
        },
        "data_harvest" => {
          description: "Run exploits + stage all CRITICAL data-theft payloads",
          steps: [
            { cmd: "exploit",  mod: "exploits/android/sql_injection" },
            { cmd: "exploit",  mod: "exploits/android/ipc_bypass" },
            { cmd: "payload",  mod: "payloads/android/credential_stealer" },
            { cmd: "payload",  mod: "payloads/android/data_exfiltration" },
            { cmd: "payload",  mod: "payloads/android/token_extractor" },
            { cmd: "payload",  mod: "payloads/android/keylogger" },
            { cmd: "report",   mod: nil },
          ]
        },
        "recon" => {
          description: "Auxiliary recon only — no exploitation",
          steps: [
            { cmd: "auxiliary", mod: "auxiliary/android/apk_info_scanner" },
            { cmd: "auxiliary", mod: "auxiliary/android/permission_analyzer" },
            { cmd: "report",    mod: nil },
          ]
        },
        "owasp_top5" => {
          description: "Cover OWASP M1–M5 critical categories",
          steps: [
            { cmd: "exploit", mod: "exploits/android/ipc_bypass" },
            { cmd: "exploit", mod: "exploits/android/clipboard_hijack" },
            { cmd: "exploit", mod: "exploits/android/deeplink_injection" },
            { cmd: "exploit", mod: "exploits/android/ipc_bypass" },
            { cmd: "exploit", mod: "exploits/android/webview_rce" },
            { cmd: "exploit", mod: "exploits/android/sql_injection" },
            { cmd: "report",  mod: nil },
          ]
        },
      }.freeze

      def initialize(framework, advisor = nil)
        @framework      = framework
        @session        = framework.session
        @advisor        = advisor
        @jobs           = []
        @user_workflows = {}
        @workflow_dir   = "./workflows"
        load_saved_workflows
      end

      # -----------------------------------------------------------------------
      # autorun <apk_path> — runs full_scan workflow automatically
      # -----------------------------------------------------------------------
      def autorun(apk_path, options = {})
        wf_name = options[:workflow] || "full_scan"
        banner("AUTORUN — #{wf_name.upcase}")
        puts "  \e[36mTarget:\e[0m #{apk_path}"
        puts "  \e[36mWorkflow:\e[0m #{wf_name}"
        puts "  \e[36mStarted:\e[0m #{Time.now.strftime('%H:%M:%S')}"
        puts ""

        @session.set_option(:TARGET, apk_path)
        run_workflow(wf_name, apk_path)
      end

      # -----------------------------------------------------------------------
      # workflow run <name> [TARGET=<path>]
      # -----------------------------------------------------------------------
      def run_workflow(name, apk_path = nil)
        wf = find_workflow(name)
        return err("Workflow '#{name}' not found. Use 'workflow list' to see available.") unless wf

        target = apk_path || @session.get_option(:TARGET)
        return err("No TARGET set. Usage: workflow run #{name} TARGET=/path/to.apk") unless target

        @session.set_option(:TARGET, target)

        job = start_job(name, target)
        banner("RUNNING WORKFLOW: #{name.upcase}")
        puts "  #{wf[:description]}"
        puts "  Steps: #{wf[:steps].size}  |  Target: #{target}"
        puts ""

        total   = wf[:steps].size
        passed  = 0
        failed  = 0
        results = []

        wf[:steps].each_with_index do |step, i|
          step_num = i + 1
          print_step_banner(step_num, total, step[:mod] || "report generate")

          begin
            result = execute_step(step, target)
            results << result
            passed += 1
            status_ok("Step #{step_num} complete")
          rescue => e
            failed += 1
            status_err("Step #{step_num} failed: #{e.message}")
            results << { status: "error", error: e.message }
          end

          sleep(0.3)  # small pause between steps for readability
        end

        finish_job(job, passed, failed)
        print_workflow_summary(name, results, passed, failed)
      end

      # -----------------------------------------------------------------------
      # workflow list — show all built-in and user-defined workflows
      # -----------------------------------------------------------------------
      def list_workflows
        banner("AVAILABLE WORKFLOWS")
        all = BUILT_IN_WORKFLOWS.merge(@user_workflows)
        all.each do |name, wf|
          tag = @user_workflows.key?(name) ? "\e[35m[custom]\e[0m" : "\e[36m[built-in]\e[0m"
          puts "  #{tag} \e[32m#{name.ljust(20)}\e[0m #{wf[:description]}"
          puts "         Steps: #{wf[:steps].size}"
        end
        puts ""
        puts "  \e[33mUsage:\e[0m workflow run <name> [TARGET=/path/to.apk]"
        puts "  \e[33mCreate:\e[0m workflow save <name>"
        puts ""
      end

      # -----------------------------------------------------------------------
      # workflow save <name> — save current session commands as workflow
      # -----------------------------------------------------------------------
      def save_workflow(name)
        history = @session.history
        return err("No command history to save.") if history.empty?

        steps = history
          .map { |h| h[:command] }
          .reject { |c| c.start_with?("workflow", "jobs", "help", "exit", "quit") }
          .map    { |c| parse_command_to_step(c) }
          .compact

        @user_workflows[name] = {
          description: "Custom workflow saved from session on #{Time.now.strftime('%Y-%m-%d %H:%M')}",
          steps:       steps,
          saved_at:    Time.now.iso8601,
        }
        persist_workflows
        ok("Workflow '#{name}' saved (#{steps.size} steps). Use: workflow run #{name}")
      end

      # -----------------------------------------------------------------------
      # jobs — show all automation job history
      # -----------------------------------------------------------------------
      def list_jobs
        banner("JOBS")
        if @jobs.empty?
          puts "  No jobs run yet. Use 'autorun <apk>' or 'workflow run <name>'."
        else
          @jobs.each do |job|
            status_color = job[:status] == "done" ? "\e[32m" : "\e[31m"
            puts "  #{status_color}[#{job[:id]}]\e[0m #{job[:workflow].ljust(20)} " \
                 "#{job[:status].ljust(8)} " \
                 "Target: #{job[:target]}  " \
                 "Started: #{job[:started_at]}  " \
                 "Passed: #{job[:passed] || '?'}/#{job[:total] || '?'}"
          end
        end
        puts ""
      end

      # -----------------------------------------------------------------------
      # workflow delete <name>
      # -----------------------------------------------------------------------
      def delete_workflow(name)
        return err("Cannot delete built-in workflow '#{name}'.") if BUILT_IN_WORKFLOWS.key?(name)
        return err("Workflow '#{name}' not found.") unless @user_workflows.key?(name)

        @user_workflows.delete(name)
        persist_workflows
        ok("Workflow '#{name}' deleted.")
      end

      private

      # -----------------------------------------------------------------------
      # Execute one workflow step
      # -----------------------------------------------------------------------
      def execute_step(step, target)
        case step[:cmd]
        when "exploit", "auxiliary"
          mod_meta = @framework.modules[step[:mod]]
          return { status: "skip", reason: "module #{step[:mod]} not found" } unless mod_meta

          @session.load_module(mod_meta)
          @session.set_option(:TARGET, target)
          @framework.dispatcher.execute_module(mod_meta, { TARGET: target })

        when "payload"
          mod_meta = @framework.modules[step[:mod]]
          return { status: "skip", reason: "payload #{step[:mod]} not found" } unless mod_meta

          @session.load_module(mod_meta)
          @session.set_option(:TARGET, target)
          @framework.dispatcher.execute_module(mod_meta, { TARGET: target })

        when "report"
          output_dir = @session.get_option(:OUTPUT) || "./reports"
          FileUtils.mkdir_p(output_dir) rescue nil

          owasp = MPF::Engines::OWASPEngine.new(@session.results).generate_compliance_report
          chains = MPF::Engines::ChainReasoner.new(@session.results).generate_chains

          json_r = MPF::Reporters::JSONReporter.new(owasp, chains, @session)
          html_r = MPF::Reporters::HTMLReporter.new(owasp, chains, @session)
          json_r.generate("#{output_dir}/mpf_report.json")
          html_r.generate("#{output_dir}/mpf_report.html")
          { status: "done", reports: [json_r, html_r] }

        when "analyze"
          @framework.dispatcher.run_full_analysis(target)

        else
          { status: "skip", reason: "unknown step type: #{step[:cmd]}" }
        end
      end

      # -----------------------------------------------------------------------
      # Job tracking
      # -----------------------------------------------------------------------
      def start_job(name, target)
        job = {
          id:         @jobs.size + 1,
          workflow:   name,
          target:     target,
          status:     "running",
          started_at: Time.now.strftime('%H:%M:%S'),
          total:      find_workflow(name)&.dig(:steps)&.size || 0,
        }
        @jobs << job
        job
      end

      def finish_job(job, passed, failed)
        job[:status]   = failed.zero? ? "done" : "partial"
        job[:passed]   = passed
        job[:failed]   = failed
        job[:ended_at] = Time.now.strftime('%H:%M:%S')
      end

      def find_workflow(name)
        BUILT_IN_WORKFLOWS[name] || @user_workflows[name]
      end

      def parse_command_to_step(cmd_str)
        parts = cmd_str.strip.split(/\s+/, 3)
        case parts[0]
        when "use"
          path = parts[1].to_s
          type = path.start_with?("exploits") ? "exploit" :
                 path.start_with?("payloads") ? "payload" : "auxiliary"
          { cmd: type, mod: path }
        when "report"
          { cmd: "report", mod: nil }
        when "analyze"
          { cmd: "analyze", mod: nil }
        end
      end

      # -----------------------------------------------------------------------
      # Persistence
      # -----------------------------------------------------------------------
      def load_saved_workflows
        path = "#{@workflow_dir}/user_workflows.json"
        return unless File.exist?(path)
        raw = JSON.parse(File.read(path), symbolize_names: true)
        raw.each do |name, wf|
          wf[:steps] = (wf[:steps] || []).map { |s| s.transform_keys(&:to_sym) }
          @user_workflows[name.to_s] = wf
        end
      rescue
        @user_workflows = {}
      end

      def persist_workflows
        FileUtils.mkdir_p(@workflow_dir) rescue nil
        path = "#{@workflow_dir}/user_workflows.json"
        File.write(path, JSON.pretty_generate(@user_workflows))
      rescue
      end

      # -----------------------------------------------------------------------
      # Display helpers
      # -----------------------------------------------------------------------
      def banner(title)
        w = title.length + 6
        puts "\n\e[36m  ╔#{'═' * w}╗\e[0m"
        puts "\e[36m  ║   #{title}   ║\e[0m"
        puts "\e[36m  ╚#{'═' * w}╝\e[0m\n"
      end

      def print_step_banner(num, total, label)
        pct  = (num.to_f / total * 100).round
        bar  = ('█' * (pct / 5)) + ('░' * (20 - pct / 5))
        puts "  \e[36m[#{num.to_s.rjust(2)}/#{total}]\e[0m [#{bar}] #{pct}%  \e[33m#{label}\e[0m"
      end

      def print_workflow_summary(name, results, passed, failed)
        puts "\n\e[36m  ┌─ WORKFLOW COMPLETE: #{name.upcase} ─┐\e[0m"
        puts "  │  Steps passed : \e[32m#{passed}\e[0m"
        puts "  │  Steps failed : #{failed > 0 ? "\e[31m#{failed}\e[0m" : "\e[32m0\e[0m"}"
        puts "  │  Total finds  : \e[36m#{@session.results.size}\e[0m"
        puts "  │  Report saved : \e[32m#{@session.get_option(:OUTPUT) || './reports'}/\e[0m"
        puts "  └───────────────────────────────────\n"
      end

      def ok(msg)
        puts("\e[32m[+]\e[0m \#{msg}")
      end
      def err(msg)
        puts("\e[31m[-]\e[0m \#{msg}")
      end
      def status_ok(msg)
        puts("      \e[32m[OK]\e[0m #{msg}")
      end

      def status_err(msg)
        puts("      \e[31m[FAIL]\e[0m #{msg}")
      end
    end
  end
end
