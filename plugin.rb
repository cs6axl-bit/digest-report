# name: digest-report
# about: POST to external endpoint after digest email is sent (failsafe, async)
# version: 0.3
# authors: you

after_initialize do
  require "net/http"
  require "uri"

  module ::DigestReport
    PLUGIN_NAME = "digest-report"

    # =========================
    # HARD-CODED SETTINGS (edit here)
    # =========================
    ENABLED = true

    ENDPOINT_URL  = "https://ai.templetrends.com/digest_report.php" # <-- change
    EMAIL_ID_VALUE = "12345"                                              # fixed value, as requested

    # Timeouts (keep short so jobs can't hang workers too long)
    OPEN_TIMEOUT_SECONDS  = 3
    READ_TIMEOUT_SECONDS  = 5
    WRITE_TIMEOUT_SECONDS = 5

    # Sidekiq retry count (small, so failures don't pile up)
    JOB_RETRY_COUNT = 3
    # =========================

    def self.log(msg)
      Rails.logger.info("[#{PLUGIN_NAME}] #{msg}")
    rescue StandardError
      # swallow
    end

    def self.log_error(msg)
      Rails.logger.error("[#{PLUGIN_NAME}] #{msg}")
    rescue StandardError
      # swallow
    end

    def self.enabled?
      return false unless ENABLED
      return false if ENDPOINT_URL.to_s.strip.empty?
      true
    rescue StandardError
      false
    end
  end

  class ::Jobs::DigestReportPostback < ::Jobs::Base
    sidekiq_options queue: "low", retry: ::DigestReport::JOB_RETRY_COUNT

    def execute(args)
      begin
        return unless ::DigestReport.enabled?

        url      = ::DigestReport::ENDPOINT_URL.to_s.strip
        email_id = ::DigestReport::EMAIL_ID_VALUE.to_s

        user_email = args[:user_email].to_s.strip
        if user_email.empty?
          ::DigestReport.log_error("Missing user_email in job args; sending anyway with blank user_email")
        end

        uri =
          begin
            URI.parse(url)
          rescue StandardError => e
            ::DigestReport.log_error("Invalid ENDPOINT_URL #{url.inspect} err=#{e.class}: #{e.message}")
            return
          end

        unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
          ::DigestReport.log_error("Invalid ENDPOINT_URL scheme (must be http/https): #{url.inspect}")
          return
        end

        body = URI.encode_www_form([
          ["email_id", email_id],
          ["user_email", user_email]
        ])

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (uri.scheme == "https")
        http.open_timeout = ::DigestReport::OPEN_TIMEOUT_SECONDS
        http.read_timeout = ::DigestReport::READ_TIMEOUT_SECONDS
        http.write_timeout = ::DigestReport::WRITE_TIMEOUT_SECONDS if http.respond_to?(:write_timeout=)

        req = Net::HTTP::Post.new(uri.request_uri)
        req["Content-Type"] = "application/x-www-form-urlencoded"
        req["User-Agent"] = "Discourse/#{Discourse::VERSION::STRING} #{::DigestReport::PLUGIN_NAME}"
        req.body = body

        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

        begin
          res = http.start { |h| h.request(req) }
          ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round

          code = res.code.to_i
          if code >= 200 && code < 300
            ::DigestReport.log("POST OK code=#{res.code} ms=#{ms} email_id=#{email_id} user_email_present=#{!user_email.empty?}")
          else
            ::DigestReport.log_error(
              "POST FAIL code=#{res.code} ms=#{ms} email_id=#{email_id} user_email_present=#{!user_email.empty?} body=#{res.body.to_s[0, 500].inspect}"
            )
          end
        rescue StandardError => e
          ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round
          ::DigestReport.log_error("POST ERROR ms=#{ms} email_id=#{email_id} user_email_present=#{!user_email.empty?} err=#{e.class}: #{e.message}")
        ensure
          begin
            http.finish if http.started?
          rescue StandardError
            # swallow
          end
        end
      rescue StandardError => e
        ::DigestReport.log_error("JOB CRASH err=#{e.class}: #{e.message}")
      end
    end
  end

  DiscourseEvent.on(:after_email_send) do |message, email_type|
    begin
      next unless ::DigestReport.enabled?
      next unless email_type.to_s == "digest"

      recipient =
        begin
          Array(message&.to).first.to_s.strip
        rescue StandardError
          ""
        end

      Jobs.enqueue(:digest_report_postback, user_email: recipient)
      ::DigestReport.log("Enqueued postback user_email_present=#{!recipient.empty?}")
    rescue StandardError => e
      ::DigestReport.log_error("ENQUEUE ERROR err=#{e.class}: #{e.message}")
    end
  end
end
