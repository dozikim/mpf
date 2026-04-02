# =============================================================================
# MPF Tab Completion Engine
# Metasploit-style smart tab completion for every command context
# =============================================================================

require 'readline'

module MPF
  module CLI
    class TabCompleter
      COMMANDS = %w[
        use set show run exploit analyze report search
        help info back exit quit autorun workflow jobs
      ].freeze

      SHOW_ARGS   = %w[options modules exploits payloads auxiliary all].freeze
      REPORT_ARGS = %w[generate].freeze
      SET_OPTS    = %w[TARGET PAYLOAD OUTPUT LHOST LPORT THREADS VERBOSE TIMEOUT].freeze

      def initialize(framework)
        @framework = framework
        @session   = framework.session
        setup!
      end

      def setup!
        Readline.completion_append_character = ' '
        Readline.completion_proc = method(:complete)
      end

      # -----------------------------------------------------------------------
      # Main completion dispatcher
      # -----------------------------------------------------------------------
      def complete(input)
        line = Readline.line_buffer.to_s
        tokens = line.split(/\s+/, -1)   # keep trailing space token
        word   = input.to_s

        # Nothing typed yet → show all commands
        return filter(COMMANDS, word) if tokens.empty?

        cmd = tokens[0].downcase

        case cmd
        when 'use'
          complete_use(word, tokens)
        when 'set'
          complete_set(word, tokens)
        when 'show'
          filter(SHOW_ARGS, word)
        when 'report'
          filter(REPORT_ARGS, word)
        when 'search'
          complete_search(word)
        when 'analyze', 'autorun'
          complete_path(word)          # filesystem path completion
        when 'workflow'
          filter(%w[run list delete save load], word)
        else
          # Still typing the command itself
          filter(COMMANDS, word)
        end
      end

      private

      # -----------------------------------------------------------------------
      # use <module_path> – three-level path completion
      # -----------------------------------------------------------------------
      def complete_use(word, tokens)
        all_paths = @framework.modules.keys

        # Level 0: no slash yet → show top-level prefixes
        if word.empty? || !word.include?('/')
          prefixes = %w[exploits/ payloads/ auxiliary/]
          return filter(prefixes, word)
        end

        parts = word.split('/')

        # Level 1: "exploits/" → show "exploits/android/"
        if parts.size == 1
          mid = all_paths.map { |p| p.split('/')[0..1].join('/') + '/' }.uniq
          return filter(mid, word)
        end

        # Level 2+: "exploits/android/" → show full paths
        filter(all_paths, word)
      end

      # -----------------------------------------------------------------------
      # set <OPTION> <value> – option-name then value hints
      # -----------------------------------------------------------------------
      def complete_set(word, tokens)
        # First arg after 'set' → option names
        if tokens.size <= 2
          opts = current_module_options + SET_OPTS
          return filter(opts.map(&:to_s).uniq, word)
        end

        # Second arg → value hints based on option key
        opt_key = tokens[1].upcase.to_sym
        case opt_key
        when :TARGET, :OUTPUT
          complete_path(word)
        when :PAYLOAD
          all_payloads = @framework.modules.keys.select { |k| k.start_with?('payloads/') }
          filter(all_payloads, word)
        when :VERBOSE
          filter(%w[true false], word)
        when :LHOST
          filter(%w[127.0.0.1 0.0.0.0], word)
        when :LPORT
          filter(%w[4444 4445 8080 443 1234], word)
        when :THREADS
          filter(%w[1 2 4 8], word)
        else
          []
        end
      end

      # -----------------------------------------------------------------------
      # search – OWASP category shortcuts + module keywords
      # -----------------------------------------------------------------------
      def complete_search(word)
        owasp = %w[M1 M2 M3 M4 M5 M6 M7 M8 M9 M10]
        keys  = %w[injection bypass rce hijack deeplink broadcast clipboard
                   fragment tapjacking exfiltration shell keylogger credential
                   sms gps screen token persistence log spoof scanner analyzer]
        filter((owasp + keys), word)
      end

      # -----------------------------------------------------------------------
      # Filesystem path completion (for TARGET / analyze)
      # -----------------------------------------------------------------------
      def complete_path(word)
        word = word.to_s
        pattern = word.empty? ? './*' : "#{word}*"
        paths   = Dir.glob(pattern).map do |p|
          File.directory?(p) ? "#{p}/" : p
        end
        paths.empty? ? [] : paths
      rescue
        []
      end

      # -----------------------------------------------------------------------
      # Helpers
      # -----------------------------------------------------------------------
      def filter(list, word)
        word = word.to_s
        word.empty? ? list : list.select { |i| i.start_with?(word) }
      end

      def current_module_options
        mod = @session.active_module
        return [] unless mod
        (mod[:options] || {}).keys.map(&:to_s)
      end
    end
  end
end
