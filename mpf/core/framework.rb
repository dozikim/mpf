# =============================================================================
# MPF Core Framework – Module Registry, Session Orchestration
# =============================================================================

require_relative 'session'
require_relative 'dispatcher'

module MPF
  module Core
    class Framework
      attr_reader :session, :dispatcher, :modules

      EXPLOIT_MODULES = %w[
        sql_injection  ipc_bypass  webview_rce  intent_hijacking
        deeplink_injection  broadcast_receiver_exploit  clipboard_hijack
        fragment_injection  tapjacking
      ].freeze

      PAYLOAD_MODULES = %w[
        data_exfiltration  reverse_shell  persistence_agent  keylogger
        screen_capture  gps_tracker  contact_harvester  sms_interceptor
        clipboard_spy  credential_stealer  token_extractor  log_injector
        broadcast_spoofer
      ].freeze

      AUXILIARY_MODULES = %w[
        apk_info_scanner  permission_analyzer
      ].freeze

      def initialize(session)
        @session    = session
        @modules    = load_module_registry
        @dispatcher = Dispatcher.new(self)
        log_info("Framework initialized — #{@modules.size} modules loaded")
      end

      def load_module_registry
        registry = {}
        EXPLOIT_MODULES.each   { |m| registry["exploits/android/#{m}"]   = build_module_meta(:exploit, m) }
        PAYLOAD_MODULES.each   { |m| registry["payloads/android/#{m}"]   = build_module_meta(:payload, m) }
        AUXILIARY_MODULES.each { |m| registry["auxiliary/android/#{m}"]  = build_module_meta(:auxiliary, m) }
        registry
      end

      def find_module(path)
        @modules[path] || @modules.select { |k, _| k.include?(path) }.first&.last
      end

      def search_modules(term)
        @modules.select { |k, _| k.include?(term.downcase) }
      end

      def stats
        {
          total:     @modules.size,
          exploits:  EXPLOIT_MODULES.size,
          payloads:  PAYLOAD_MODULES.size,
          auxiliary: AUXILIARY_MODULES.size,
          version:   MPF::VERSION
        }
      end

      private

      def build_module_meta(type, name)
        {
          name: name,
          type: type,
          path: "modules/#{type}s/#{name}.rb",
          description: module_description(type, name),
          owasp: owasp_mapping(name),
          severity: severity_mapping(name),
          options: default_options(type)
        }
      end

      def module_description(type, name)
        descriptions = {
          sql_injection:              "Exploits insecure SQL query construction in Android ContentProviders",
          ipc_bypass:                 "Bypasses IPC security via exported components and implicit intents",
          webview_rce:                "Remote code execution via WebView addJavascriptInterface misuse",
          intent_hijacking:           "Intercepts implicit intents to steal sensitive data between components",
          deeplink_injection:         "Injects malicious data via unvalidated deep link URI parameters",
          broadcast_receiver_exploit: "Exploits unprotected broadcast receivers to trigger unauthorized actions",
          clipboard_hijack:           "Monitors and hijacks clipboard content including passwords and tokens",
          fragment_injection:         "Injects malicious fragments via exported PreferenceActivity",
          tapjacking:                 "Overlays transparent views to capture touch events from victims",
          data_exfiltration:          "Extracts sensitive data from device storage and sends to C2 server",
          reverse_shell:              "Establishes reverse shell connection back to attacker machine",
          persistence_agent:          "Installs persistent backdoor that survives app restarts",
          keylogger:                  "Captures all keyboard input including passwords and PINs",
          screen_capture:             "Silently captures screenshots and screen recordings",
          gps_tracker:                "Continuously tracks device GPS location coordinates",
          contact_harvester:          "Exports full contact list to attacker-controlled server",
          sms_interceptor:            "Intercepts incoming and outgoing SMS messages including OTPs",
          clipboard_spy:              "Monitors clipboard for credentials, tokens and sensitive strings",
          credential_stealer:         "Extracts stored credentials from SharedPreferences and databases",
          token_extractor:            "Extracts OAuth tokens and API keys from app storage",
          log_injector:               "Injects malicious entries into application log files",
          broadcast_spoofer:          "Sends spoofed broadcast intents to trigger unintended app behavior",
          apk_info_scanner:           "Extracts comprehensive metadata and structure from APK files",
          permission_analyzer:        "Analyzes declared permissions against OWASP risk categories"
        }
        descriptions[name.to_sym] || "#{type.to_s.capitalize} module: #{name.gsub('_', ' ').capitalize}"
      end

      def owasp_mapping(name)
        mappings = {
          sql_injection: "M2, M7", ipc_bypass: "M1", webview_rce: "M1, M7",
          intent_hijacking: "M1", deeplink_injection: "M1, M7",
          broadcast_receiver_exploit: "M1", clipboard_hijack: "M2",
          fragment_injection: "M1, M4", tapjacking: "M1",
          data_exfiltration: "M2", reverse_shell: "M1",
          persistence_agent: "M8", keylogger: "M2, M4",
          screen_capture: "M2", gps_tracker: "M2",
          contact_harvester: "M2", sms_interceptor: "M2",
          clipboard_spy: "M2", credential_stealer: "M2, M4",
          token_extractor: "M4, M5", log_injector: "M7",
          broadcast_spoofer: "M1", apk_info_scanner: "M10",
          permission_analyzer: "M1, M10"
        }
        mappings[name.to_sym] || "M1"
      end

      def severity_mapping(name)
        critical = %i[webview_rce sql_injection reverse_shell credential_stealer data_exfiltration keylogger]
        high     = %i[ipc_bypass intent_hijacking fragment_injection persistence_agent token_extractor sms_interceptor]
        critical.include?(name.to_sym) ? "CRITICAL" : high.include?(name.to_sym) ? "HIGH" : "MEDIUM"
      end

      def default_options(type)
        base = { TARGET: { required: true, desc: "Path to target APK file" } }
        base[:PAYLOAD]  = { required: false, desc: "Payload module path" }  if type == :exploit
        base[:OUTPUT]   = { required: false, desc: "Output report directory", default: "./reports" }
        base
      end

      def log_info(msg)
        puts "\e[36m[MPF]\e[0m #{msg}"
      end
    end
  end
end
