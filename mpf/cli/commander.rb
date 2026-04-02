# =============================================================================
# MPF CLI Commander v2.0 — Metasploit-Style REPL
# New: Tab Completion  |  Guided Advisor  |  Automation Engine
# =============================================================================

require 'readline'
require_relative 'tab_completer'
require_relative 'guided_advisor'
require_relative '../automation/engine'

module MPF
  module CLI
    class Commander
      def initialize(framework)
        @framework  = framework
        @session    = framework.session
        @completer  = TabCompleter.new(framework)
        @advisor    = GuidedAdvisor.new(framework)
        @automation = Automation::Engine.new(framework, @advisor)
      end

      def start_repl
        loop do
          prompt = build_prompt
          input  = Readline.readline(prompt, true)
          break if input.nil?
          input.strip!
          next if input.empty?
          @session.add_history(input)
          result = dispatch(input)
          break if result == :exit
        end
        puts "\n\e[36m[MPF]\e[0m Session ended. Findings: #{@session.results.size}. Stay ethical."
      end

      private

      def build_prompt
        if @session.active_module
          m = @session.active_module
          sc = { "CRITICAL" => "\e[31m", "HIGH" => "\e[33m", "MEDIUM" => "\e[33m", "LOW" => "\e[32m" }[m[:severity]] || ""
          "\e[36mmpf\e[0m \e[35m#{m[:type]}(\e[0m\e[36m#{m[:name]}\e[0m\e[35m)\e[0m \e[90m#{sc}[#{m[:severity]}]\e[0m > "
        else
          "\e[36mmpf\e[0m > "
        end
      end

      def dispatch(input)
        parts   = input.split(/\s+/, 4)
        command = parts[0]&.downcase
        args    = parts[1..]
        case command
        when "use"              then cmd_use(args)
        when "set"              then cmd_set(args)
        when "show"             then cmd_show(args)
        when "run", "exploit"   then cmd_run
        when "analyze"          then cmd_analyze(args)
        when "report"           then cmd_report(args)
        when "search"           then cmd_search(args)
        when "info"             then cmd_info
        when "back"             then cmd_back
        when "autorun"          then cmd_autorun(args)
        when "workflow"         then cmd_workflow(args)
        when "jobs"             then @automation.list_jobs
        when "help"             then cmd_help
        when "exit", "quit"     then return :exit
        else
          puts "\e[31m[-]\e[0m Unknown command: '\e[33m#{command}\e[0m'. Type \e[36mhelp\e[0m or press TAB."
        end
        nil
      end

      # use ---------------------------------------------------------------
      def cmd_use(args)
        return err("Usage: use <module_path>   [press TAB to autocomplete]") if args.empty?
        mod = @framework.find_module(args[0])
        unless mod
          candidates = @framework.modules.keys.select { |k| k.include?(args[0].downcase) }
          if candidates.size == 1
            mod = @framework.modules[candidates[0]]
            info("Fuzzy matched: \e[36m#{candidates[0]}\e[0m")
          elsif candidates.size > 1
            puts "\e[33m[~]\e[0m Ambiguous. Did you mean one of these?"
            candidates.first(6).each { |c| puts "    \e[36m→ use #{c}\e[0m" }
            return
          end
        end
        if mod
          @session.load_module(mod)
          ok("Module loaded: \e[36m#{mod[:name]}\e[0m  [\e[35m#{mod[:type]}\e[0m]")
          ok("Severity: #{colorize_severity(mod[:severity])}  |  OWASP: \e[33m#{mod[:owasp]}\e[0m")
          puts "  \e[90m#{mod[:description]}\e[0m"
          @advisor.after_module_loaded(mod)
        else
          err("Module not found: '#{args[0]}'. Try: \e[32msearch #{args[0].split('/').last}\e[0m")
        end
      end

      # set ---------------------------------------------------------------
      def cmd_set(args)
        return err("Usage: set <OPTION> <value>   [TAB after 'set ' for option names]") if args.size < 2
        key = args[0].upcase
        val = args[1..].join(" ")
        @session.set_option(key, val)
        ok("\e[36m#{key}\e[0m => \e[32m#{val}\e[0m")
        if key == "TARGET"
          mod = @session.active_module
          mod ? info("TARGET set. Type \e[32mrun\e[0m to execute.") :
                info("TARGET set. Load a module: \e[32muse exploits/android/\e[0m + TAB")
        end
      end

      # show ---------------------------------------------------------------
      def cmd_show(args)
        case args[0]&.downcase
        when "options"             then show_options
        when "modules","exploits"  then show_module_list(:exploit)
        when "payloads"            then show_module_list(:payload)
        when "auxiliary"           then show_module_list(:auxiliary)
        when "all"                 then [:exploit,:payload,:auxiliary].each { |t| show_module_list(t) }
        else
          @session.active_module ? show_options : [:exploit,:payload,:auxiliary].each { |t| show_module_list(t) }
        end
      end

      def show_options
        mod = @session.active_module
        return info("No module loaded. Type: \e[32muse exploits/android/\e[0m + TAB") unless mod
        puts "\n  \e[36m#{mod[:name]}\e[0m  [\e[35m#{mod[:type]}\e[0m]  #{colorize_severity(mod[:severity])}  OWASP: \e[33m#{mod[:owasp]}\e[0m"
        puts "  \e[90m#{mod[:description]}\e[0m"
        puts "\n  \e[35mOptions:\e[0m"
        puts "  #{"Name".ljust(14)} #{"Value".ljust(32)} #{"Required".ljust(10)} Description"
        puts "  #{'-'*72}"
        (mod[:options] || {}).each do |opt, meta|
          val = @session.get_option(opt) || meta[:default] || ""
          req = meta[:required] ? "\e[31mYes\e[0m" : "\e[32mNo\e[0m "
          puts "  #{opt.to_s.ljust(14)} #{val.to_s.ljust(32)} #{req.ljust(14)} #{meta[:desc]}"
        end
        puts ""
        missing = (mod[:options] || {}).select { |_, m| m[:required] && @session.get_option(_).nil? }.keys
        if missing.any?
          puts "  \e[31m[!]\e[0m Required not set: #{missing.join(', ')}"
          puts "  \e[33m→\e[0m set #{missing.first} <value>   [TAB for hints]"
        else
          puts "  \e[32m[✓]\e[0m All required options set. Type \e[32mrun\e[0m to execute."
        end
        puts ""
      end

      def show_module_list(type)
        mods = @framework.modules.select { |_, m| m[:type] == type }
        puts "\n  \e[35m#{type.to_s.capitalize} Modules (#{mods.size}):\e[0m"
        puts "  #{"Path".ljust(42)} #{"Severity".ljust(10)} OWASP"
        puts "  #{'-'*68}"
        mods.each { |path, m| puts "  #{path.ljust(42)} #{colorize_severity(m[:severity]).ljust(18)} #{m[:owasp]}" }
        puts "\n  \e[33mTip:\e[0m Type \e[36muse exploits/android/\e[0m then press TAB.\n\n"
      end

      # run ---------------------------------------------------------------
      def cmd_run
        mod = @session.active_module
        return err("No module loaded. Type \e[32muse \e[0m+ TAB.") unless mod
        target = @session.get_option(:TARGET)
        return err("TARGET not set. Use: \e[32mset TARGET /path/to/app.apk\e[0m") unless target
        puts "\n\e[35m[*]\e[0m Executing \e[35m#{mod[:type]}\e[0m: \e[36m#{mod[:name]}\e[0m"
        puts "    Target:   \e[90m#{target}\e[0m"
        puts "    OWASP:    \e[33m#{mod[:owasp]}\e[0m  Severity: #{colorize_severity(mod[:severity])}"
        puts "    \e[33m[SAFE MODE]\e[0m Evidence-only — no persistent changes.\n\n"
        result = @framework.dispatcher.execute_module(mod, { TARGET: target })
        ok("Complete. Status: \e[36m#{result[:status]}\e[0m  Findings: \e[32m#{result[:findings] || 0}\e[0m\n")
        @advisor.after_exploit(mod, result)
      end

      # analyze ---------------------------------------------------------------
      def cmd_analyze(args)
        return err("Usage: analyze <path/to/app.apk>") if args.empty?
        puts "\n\e[36m[*]\e[0m Starting full analysis: \e[33m#{args[0]}\e[0m"
        result = @framework.dispatcher.run_full_analysis(args[0])
        puts "\n\e[32m[+]\e[0m Analysis complete!"
        puts "    Findings:      \e[31m#{result[:findings].size}\e[0m"
        puts "    Attack Chains: \e[33m#{result[:chains].size}\e[0m"
        puts "    OWASP Grade:   \e[36m#{result[:owasp][:compliance_grade]}\e[0m  Score: #{result[:owasp][:overall_score]}%"
        @advisor.after_analysis(result)
      end

      # report ---------------------------------------------------------------
      def cmd_report(args)
        return err("Usage: report generate") unless args[0]&.downcase == "generate"
        dir = @session.get_option(:OUTPUT) || "./reports"
        require 'fileutils'
        FileUtils.mkdir_p(dir) rescue nil
        owasp  = Engines::OWASPEngine.new(@session.results).generate_compliance_report
        chains = Engines::ChainReasoner.new(@session.results).generate_chains
        Reporters::JSONReporter.new(owasp, chains, @session).generate("#{dir}/mpf_report.json")
        Reporters::HTMLReporter.new(owasp, chains, @session).generate("#{dir}/mpf_report.html")
        ok("Reports saved → \e[36m#{dir}/\e[0m")
        info("Open \e[32m#{dir}/mpf_report.html\e[0m in browser for interactive report.")
      end

      # search ---------------------------------------------------------------
      def cmd_search(args)
        return err("Usage: search <term>  [TAB for OWASP categories & keywords]") if args.empty?
        term = args.join(" ")
        res  = @framework.search_modules(term)
        if res.empty?
          info("No modules for '#{term}'. Try: M1..M10, injection, bypass, rce, credential")
        else
          puts "\n  \e[35mMatches for '\e[36m#{term}\e[35m' (#{res.size}):\e[0m"
          puts "  #{"Path".ljust(45)} Severity   OWASP"
          puts "  #{'-'*70}"
          res.each { |path,m| puts "  #{path.ljust(45)} #{colorize_severity(m[:severity]).ljust(19)} #{m[:owasp]}" }
          puts "\n  \e[33mTip:\e[0m use #{res.keys.first}\n\n"
        end
      end

      # info ---------------------------------------------------------------
      def cmd_info
        mod = @session.active_module
        return info("No module loaded.") unless mod
        puts "\n  \e[36m┌── MODULE INFO ────────────────────────────────────┐\e[0m"
        puts "  │  Name     : \e[36m#{mod[:name]}\e[0m"
        puts "  │  Type     : \e[35m#{mod[:type]}\e[0m"
        puts "  │  Severity : #{colorize_severity(mod[:severity])}"
        puts "  │  OWASP    : \e[33m#{mod[:owasp]}\e[0m"
        puts "  │  Desc     : #{mod[:description]}"
        puts "  │  File     : \e[90m#{mod[:path]}\e[0m"
        puts "  \e[36m└───────────────────────────────────────────────────┘\e[0m\n"
        @advisor.after_module_loaded(mod)
      end

      # back ---------------------------------------------------------------
      def cmd_back
        if @session.active_module
          info("Unloaded: #{@session.active_module[:name]}")
          @session.active_module = nil
          @session.reset_options
        else
          info("No module loaded.")
        end
      end

      # autorun ---------------------------------------------------------------
      def cmd_autorun(args)
        return err("Usage: autorun <path/to/app.apk> [--workflow=full_scan]") if args.empty?
        apk     = args[0]
        wf_flag = args.find { |a| a.start_with?("--workflow=") }
        wf_name = wf_flag ? wf_flag.split("=", 2).last : "full_scan"
        @automation.autorun(apk, workflow: wf_name)
      end

      # workflow ---------------------------------------------------------------
      def cmd_workflow(args)
        sub = args[0]&.downcase
        case sub
        when "run"
          name = args[1]
          return err("Usage: workflow run <n> [TARGET=/path.apk]") unless name
          target_arg = args.find { |a| a.start_with?("TARGET=") }
          target = target_arg ? target_arg.split("=", 2).last : @session.get_option(:TARGET)
          @session.set_option(:TARGET, target) if target
          @automation.run_workflow(name, target)
        when "list"    then @automation.list_workflows
        when "save"
          return err("Usage: workflow save <n>") unless args[1]
          @automation.save_workflow(args[1])
        when "delete"
          return err("Usage: workflow delete <n>") unless args[1]
          @automation.delete_workflow(args[1])
        else
          puts "\n  \e[35mworkflow commands:\e[0m"
          puts "    \e[36mworkflow list\e[0m                        show all workflows"
          puts "    \e[36mworkflow run <n> [TARGET=<apk>]\e[0m      run a workflow"
          puts "    \e[36mworkflow save <n>\e[0m                    save session as workflow"
          puts "    \e[36mworkflow delete <n>\e[0m                  delete saved workflow"
          puts "\n  \e[35mBuilt-in:\e[0m  full_scan  critical_only  data_harvest  recon  owasp_top5\n\n"
        end
      end

      # help ---------------------------------------------------------------
      def cmd_help
        c  = "\e["   # escape prefix
        r  = "\e[0m" # reset
        cy = "#{c}36m"; mg = "#{c}35m"; gn = "#{c}32m"; ye = "#{c}33m"; rd = "#{c}31m"
        puts ""
        puts "#{cy}  \u2554#{'=' * 54}\u2557#{r}"
        puts "#{cy}  \u2551         MPF Command Reference  v2.0.0               \u2551#{r}"
        puts "#{cy}  \u255A#{'=' * 54}\u255D#{r}"
        puts ""
        puts "#{mg}  MODULES#{r}"
        puts "    #{cy}use#{r} <module>           Load exploit/payload/auxiliary  [TAB]"
        puts "    #{cy}set#{r} <OPT> <val>        Set option (TARGET, PAYLOAD...)   [TAB]"
        puts "    #{cy}show#{r} [options|modules|payloads|auxiliary|all]"
        puts "    #{cy}run#{r} / #{cy}exploit#{r}           Execute loaded module"
        puts "    #{cy}info#{r}                   Detailed info + next-step hints"
        puts "    #{cy}back#{r}                   Unload module"
        puts ""
        puts "#{mg}  ANALYSIS#{r}"
        puts "    #{cy}analyze#{r} <apk>          Full 6-phase scan + guided roadmap"
        puts "    #{cy}search#{r} <term|M1..M10>  Find modules  [TAB for suggestions]"
        puts ""
        puts "#{mg}  AUTOMATION#{r}"
        puts "    #{cy}autorun#{r} <apk>                         Auto full_scan workflow"
        puts "    #{cy}autorun#{r} <apk> #{ye}--workflow=<n>#{r}"
        puts "    #{cy}workflow list#{r}                         All available workflows"
        puts "    #{cy}workflow run#{r} <n> [TARGET=<apk>]"
        puts "    #{cy}workflow save#{r} <n>                     Save session as workflow"
        puts "    #{cy}workflow delete#{r} <n>"
        puts "    #{cy}jobs#{r}                                  Job history"
        puts ""
        puts "#{mg}  REPORTING#{r}"
        puts "    #{cy}report generate#{r}        Save JSON + HTML reports"
        puts ""
        puts "#{mg}  TAB COMPLETION#{r}"
        puts "    use [TAB]                    #{ye}\u2192#{r} exploits/  payloads/  auxiliary/"
        puts "    use exploits/android/ [TAB]  #{ye}\u2192#{r} all 9 exploit names"
        puts "    set [TAB]                    #{ye}\u2192#{r} TARGET  PAYLOAD  OUTPUT  LHOST..."
        puts "    set TARGET [TAB]             #{ye}\u2192#{r} filesystem path completion"
        puts "    set PAYLOAD [TAB]            #{ye}\u2192#{r} all payload paths"
        puts "    search [TAB]                 #{ye}\u2192#{r} M1..M10 + keywords"
        puts ""
        puts "#{mg}  QUICK START#{r}"
        puts "    #{gn}mpf > analyze /path/app.apk#{r}                 full scan + roadmap"
        puts "    #{gn}mpf > autorun /path/app.apk#{r}                 fully automated"
        puts "    #{gn}mpf > workflow run data_harvest TARGET=/path/app.apk#{r}"
        puts ""
      end

      def ok(msg)
        puts("\e[32m[+]\e[0m #{msg}")
      end

      def info(msg)
        puts("\e[36m[*]\e[0m #{msg}")
      end

      def err(msg)
        puts("\e[31m[-]\e[0m #{msg}")
      end

      def colorize_severity(s)
        c = { "CRITICAL"=>"\e[31m","HIGH"=>"\e[33m","MEDIUM"=>"\e[33m","LOW"=>"\e[32m" }
        "#{c[s]||''}#{s}\e[0m"
      end
    end
  end
end
