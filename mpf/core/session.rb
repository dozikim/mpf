# =============================================================================
# MPF Core Session – State Management, Active Module Tracking
# =============================================================================

require 'time'

module MPF
  module Core
    class Session
      attr_accessor :active_module, :options, :history, :results
      attr_reader   :id, :started_at

      def initialize
        @id            = generate_id
        @started_at    = Time.now
        @active_module = nil
        @options       = {}
        @history       = []
        @results       = []
        @audit_log     = []
      end

      def set_option(key, value)
        @options[key.upcase.to_sym] = value
        log_audit("SET #{key}=#{value}")
      end

      def get_option(key)
        @options[key.upcase.to_sym]
      end

      def reset_options
        @options = {}
      end

      def load_module(mod_meta)
        @active_module = mod_meta
        @options = {}
        log_audit("USE #{mod_meta[:name]}")
      end

      def add_result(finding)
        @results << finding.merge(timestamp: Time.now.iso8601, session_id: @id)
        log_audit("FINDING: #{finding[:title]} [#{finding[:severity]}]")
      end

      def add_history(cmd)
        @history << { command: cmd, time: Time.now.iso8601 }
      end

      def export_audit_log
        @audit_log.map { |e| "[#{e[:time]}] #{e[:action]}" }.join("\n")
      end

      def summary
        {
          session_id:  @id,
          started_at:  @started_at.iso8601,
          total_finds: @results.size,
          critical:    @results.count { |r| r[:severity] == "CRITICAL" },
          high:        @results.count { |r| r[:severity] == "HIGH" },
          medium:      @results.count { |r| r[:severity] == "MEDIUM" },
          low:         @results.count { |r| r[:severity] == "LOW" }
        }
      end

      private

      def generate_id
        "MPF-#{Time.now.strftime('%Y%m%d')}-#{rand(10000..99999)}"
      end

      def log_audit(action)
        @audit_log << { time: Time.now.iso8601, action: action }
      end
    end
  end
end
