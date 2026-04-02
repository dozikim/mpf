# =============================================================================
# MPF CLI Banner – Metasploit-Inspired Interface
# =============================================================================

module MPF
  module CLI
    module Banner
      def self.display
        puts "\e[36m" + <<~BANNER
          ███╗   ███╗██████╗ ███████╗
          ████╗ ████║██╔══██╗██╔════╝
          ██╔████╔██║██████╔╝█████╗  
          ██║╚██╔╝██║██╔═══╝ ██╔══╝  
          ██║ ╚═╝ ██║██║     ██║     
          ╚═╝     ╚═╝╚═╝     ╚═╝     
        BANNER
        puts "\e[0m"
        puts "  \e[37mMobile Penetration Testing Framework\e[0m"
        puts "  \e[35mVersion 2.0.0  |  OWASP-Aligned  |  Educational Use\e[0m"
        puts "  \e[90m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
        puts "  Modules: \e[36m24\e[0m  |  OWASP Coverage: \e[32m100%\e[0m  |  Android 5.0–14"
        puts "  Type \e[33mhelp\e[0m for available commands."
        puts ""
      end
    end
  end
end
