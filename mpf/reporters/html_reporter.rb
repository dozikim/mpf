# =============================================================================
# MPF HTML Reporter – Interactive Web Compliance Report
# =============================================================================

module MPF
  module Reporters
    class HTMLReporter
      SEVERITY_COLORS = {
        "CRITICAL" => "#FF3D57",
        "HIGH"     => "#FF9100",
        "MEDIUM"   => "#FFD600",
        "LOW"      => "#00E676"
      }.freeze

      def initialize(owasp_report, chains, session)
        @owasp   = owasp_report
        @chains  = chains
        @session = session
      end

      def generate(output_path = "reports/mpf_report.html")
        FileUtils.mkdir_p(File.dirname(output_path)) rescue nil
        File.write(output_path, build_html)
        puts "\e[32m[+]\e[0m HTML report saved: #{output_path}"
        output_path
      end

      private

      def build_html
        summary = @session.summary
        sev     = @owasp[:severity_summary] || {}

        <<~HTML
          <!DOCTYPE html>
          <html lang="en">
          <head>
            <meta charset="UTF-8">
            <title>MPF Security Report</title>
            <style>
              :root { --bg:#0A0E1A;--panel:#141E35;--accent:#00D4FF;--accent2:#7B2FFF;--green:#00E676;--red:#FF3D57;--orange:#FF9100;--white:#FFFFFF;--muted:#8892A4; }
              * { box-sizing:border-box; margin:0; padding:0; }
              body { background:var(--bg); color:var(--white); font-family:'Segoe UI',Arial,sans-serif; padding:30px; }
              h1 { color:var(--accent); font-size:2rem; margin-bottom:5px; }
              h2 { color:var(--accent); font-size:1.2rem; margin:25px 0 12px; border-bottom:2px solid var(--accent2); padding-bottom:5px; }
              h3 { color:var(--accent2); font-size:1rem; margin-bottom:8px; }
              .header { border-left:5px solid var(--accent); padding:15px 20px; background:var(--panel); border-radius:6px; margin-bottom:25px; }
              .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:15px; margin-bottom:25px; }
              .card { background:var(--panel); border-radius:8px; padding:20px; text-align:center; border-top:3px solid var(--accent); }
              .card .val { font-size:2.2rem; font-weight:bold; color:var(--accent); }
              .card .lbl { font-size:0.8rem; color:var(--muted); margin-top:5px; }
              .finding { background:var(--panel); border-radius:6px; padding:15px; margin-bottom:12px; border-left:4px solid; }
              .badge { display:inline-block; padding:3px 10px; border-radius:12px; font-size:0.75rem; font-weight:bold; color:#000; margin-right:6px; }
              .CRITICAL { border-color:#FF3D57; } .badge-CRITICAL { background:#FF3D57; }
              .HIGH     { border-color:#FF9100; } .badge-HIGH     { background:#FF9100; }
              .MEDIUM   { border-color:#FFD600; } .badge-MEDIUM   { background:#FFD600; }
              .LOW      { border-color:#00E676; } .badge-LOW      { background:#00E676; }
              table { width:100%; border-collapse:collapse; background:var(--panel); border-radius:8px; overflow:hidden; }
              th { background:var(--accent2); color:#fff; padding:10px 14px; text-align:left; font-size:0.85rem; }
              td { padding:9px 14px; border-bottom:1px solid #1A2745; font-size:0.85rem; }
              tr:last-child td { border-bottom:none; }
              .chain { background:var(--panel); border-radius:8px; padding:16px; margin-bottom:12px; border-left:4px solid var(--accent2); }
              .evidence { background:#050A14; border-radius:4px; padding:10px 14px; font-family:monospace; font-size:0.82rem; color:var(--accent); margin-top:8px; white-space:pre-wrap; }
              .grade { font-size:3rem; font-weight:bold; color:var(--green); }
              footer { text-align:center; color:var(--muted); font-size:0.8rem; margin-top:40px; border-top:1px solid #1A2745; padding-top:15px; }
            </style>
          </head>
          <body>
          <div class="header">
            <h1>&#128737; MPF Security Assessment Report</h1>
            <p style="color:var(--muted)">Mobile Penetration Testing Framework v2.0.0 &nbsp;|&nbsp; Session: #{summary[:session_id]} &nbsp;|&nbsp; Generated: #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}</p>
          </div>

          <h2>Executive Summary</h2>
          <div class="grid">
            <div class="card"><div class="val grade">#{@owasp[:compliance_grade]}</div><div class="lbl">Compliance Grade</div></div>
            <div class="card"><div class="val">#{@owasp[:overall_score]}%</div><div class="lbl">Security Score</div></div>
            <div class="card"><div class="val" style="color:var(--red)">#{sev[:critical] || 0}</div><div class="lbl">Critical Findings</div></div>
            <div class="card"><div class="val" style="color:var(--orange)">#{sev[:high] || 0}</div><div class="lbl">High Findings</div></div>
            <div class="card"><div class="val" style="color:#FFD600">#{sev[:medium] || 0}</div><div class="lbl">Medium Findings</div></div>
            <div class="card"><div class="val" style="color:var(--green)">#{@chains.size}</div><div class="lbl">Attack Chains</div></div>
          </div>

          <h2>OWASP Mobile Top 10 Compliance</h2>
          <table>
            <tr><th>Category</th><th>Name</th><th>Findings</th><th>Critical</th><th>High</th><th>Risk Level</th></tr>
            #{owasp_rows}
          </table>

          <h2>Attack Chains Identified</h2>
          #{chain_html}

          <h2>Vulnerability Findings (#{@session.results.size})</h2>
          #{findings_html}

          <h2>Recommendations</h2>
          <ol style="padding-left:20px; line-height:2">
            <li>Remediate all <strong style="color:var(--red)">CRITICAL</strong> findings before next production release</li>
            <li>Implement SSL Certificate Pinning to prevent MITM attacks</li>
            <li>Enable ProGuard/R8 obfuscation and set debuggable=false</li>
            <li>Replace hardcoded credentials with Android Keystore API</li>
            <li>Conduct re-assessment after remediation to verify fixes</li>
          </ol>

          <footer>Generated by MPF – Mobile Penetration Testing Framework v2.0.0 &copy; 2026 | For educational and authorized testing use only.</footer>
          </body></html>
        HTML
      end

      def owasp_rows
        cats = @owasp[:categories] || {}
        cats.map do |cat_id, data|
          rl    = data[:risk_level] || "LOW"
          color = { "CRITICAL" => "#FF3D57", "HIGH" => "#FF9100", "MEDIUM" => "#FFD600", "LOW" => "#00E676" }[rl]
          "<tr><td><strong>#{cat_id}</strong></td><td>#{data[:name]}</td><td>#{data[:findings]}</td><td style='color:#FF3D57'>#{data[:critical]}</td><td style='color:#FF9100'>#{data[:high]}</td><td><span class='badge badge-#{rl}'>#{rl}</span></td></tr>"
        end.join("\n")
      end

      def chain_html
        return "<p style='color:var(--muted)'>No attack chains detected.</p>" if @chains.empty?
        @chains.map do |chain|
          steps = chain[:steps].each_with_index.map { |s, i| "<li>#{i+1}. #{s}</li>" }.join
          <<~HTML
            <div class="chain">
              <h3>#{chain[:id]}: #{chain[:name]} &nbsp;<span class="badge badge-#{chain[:severity]}">#{chain[:severity]}</span></h3>
              <p style="color:var(--muted);margin:6px 0">#{chain[:description]}</p>
              <p>Confidence: <strong style="color:var(--accent)">#{chain[:confidence]}%</strong> &nbsp; OWASP Path: <strong>#{chain[:owasp_chain].join(' → ')}</strong></p>
              <ol style="margin-top:8px;padding-left:20px;color:#E8EEF7;line-height:1.9">#{steps}</ol>
            </div>
          HTML
        end.join
      end

      def findings_html
        @session.results.map do |f|
          sev = f[:severity] || "LOW"
          <<~HTML
            <div class="finding #{sev}">
              <span class="badge badge-#{sev}">#{sev}</span>
              <span class="badge" style="background:var(--accent2);color:#fff">#{f[:owasp]}</span>
              <strong>#{f[:title]}</strong>
              <p style="color:var(--muted);margin:6px 0;font-size:0.85rem">#{f[:description]}</p>
              <div class="evidence">#{f[:evidence]}</div>
              <p style="margin-top:8px;font-size:0.82rem"><strong style="color:var(--green)">&#10003; Fix:</strong> #{f[:remediation]}</p>
              <p style="font-size:0.78rem;color:var(--muted);margin-top:4px">File: #{f[:file_ref]} | Line: #{f[:line_number]} | CVSS: #{f[:cvss_score]}</p>
            </div>
          HTML
        end.join
      end
    end
  end
end
