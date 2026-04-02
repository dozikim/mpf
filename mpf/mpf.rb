#!/usr/bin/env ruby
# =============================================================================
# MPF – Mobile Penetration Testing Framework
# Version: 2.0.0 | OWASP-Aligned Android Security Assessment Platform
# Author: MPF Research Team | B.Tech Final Year Project
# =============================================================================

$LOAD_PATH.unshift(File.dirname(__FILE__))

require 'time'
require 'json'
require 'fileutils'

require 'core/framework'
require 'core/session'
require 'core/dispatcher'
require 'cli/banner'
require 'cli/commander'

module MPF
  VERSION = "2.0.0"
  AUTHOR  = "MPF Research Team"
  LICENSE = "Educational Use Only"

  def self.run
    CLI::Banner.display
    session  = Core::Session.new
    framework = Core::Framework.new(session)
    commander = CLI::Commander.new(framework)
    commander.start_repl
  end
end

MPF.run if __FILE__ == $0
