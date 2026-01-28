# name: digest-report
# about: POST to external endpoint after digest email is sent (failsafe, async)
# version: 0.2
# authors: you

after_initialize do
  require "net/http"
  require "uri"

  module ::DigestPostback
    PLUGIN_NAME = "digest-report"

    # =========================
    # HARD-CODED SETTINGS (edit here)
    # =========================
    ENABLED = true

    ENDPOINT_URL = "https://ai.templetrends.com/digest_report.php" # <-- change
    EMAIL_ID_VALUE = "12345"                                             # <-- requested fixed value

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
      # swallow absolutely everything
    end

    def self.log_error(msg)
      Rails.logger.error("[#{PLUGIN_NAME}] #{msg}")
    rescue StandardError
      # swallow absolutely everything
    end

    def self.enabled?
      return false unless ENABLED
      return false if ENDPOINT_URL.to_s.strip.empty?
      true
    rescue StandardError
      false
    end
  end

  class ::Jobs::DigestPostback < ::Jobs::Base
    # Use low priority queue; limited retries so we never bog down the system
    sidekiq_options queue: "low", retry: ::DigestPostback::JOB_RETRY_COUNT

    def execute(args)
      begin
        return unless ::DigestPostback.enabled?

        url = ::DigestPostback::ENDPOINT_URL.to_s.strip
        email_id = ::DigestPostback::EMAIL_ID_VALUE.to_s

        uri =
          begin
            URI.parse(url)
          rescue StandardError => e
            ::DigestPostback.log_error("Invalid ENDPOINT_URL #{url.inspect} err=#{e.class}: #{e.message}")
            return
          end

        unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
          ::DigestPostback.log_error("Invalid ENDPOINT_URL scheme (must be http/https): #{url.inspect}")
          return
        end

        # POST body: application/x-www-form-urlencoded with only email_id=12345
        body = URI.encode_www_form([["email_id", email_id]])

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (uri.scheme == "https")
        http.open_timeout = ::DigestPostback::OPEN_TIMEOUT_SECONDS
        http.read_timeout = ::DigestPostback::READ_TIMEOUT_SECONDS
        http.write_timeout = ::DigestPostback::WRITE_TIMEOUT_SECONDS if http.respond_to?(:write_timeout=)

        req = Net::HTTP::Post.new(uri.request_uri)
        req["Content-Type"] = "application/x-www-form-urlencoded"
        req["User-Agent"] = "Discourse/#{Discourse::VERSION::STRING} #{::DigestPostback::PLUGIN_NAME}"
        req.body = body

        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

        begin
          res = http.start { |h| h.request(req) }
          ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round

          code = res.code.to_i
          if code >= 200 && code < 300
            ::DigestPostback.log("POST OK code=#{res.code} ms=#{ms} email_id=#{email_id}")
          else
            ::DigestPostback.log_error("POST FAIL code=#{res.code} ms=#{ms} email_id=#{email_id} body=#{res.body.to_s[0, 500].inspect}")
          end
        rescue StandardError => e
          ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round
          ::DigestPostback.log_error("POST ERROR ms=#{ms} email_id=#{email_id} err=#{e.class}: #{e.message}")
        ensure
          begin
            http.finish if http.started?
          rescue StandardError
            # swallow
          end
        end
      rescue StandardError => e
        # Last-ditch catch: job must never explode Sidekiq worker
        ::DigestPostback.log_error("JOB CRASH err=#{e.class}: #{e.message}")
      end
    end
  end

  # Trigger after an email is sent; enqueue job only (never network here).
  DiscourseEvent.on(:after_email_send) do |message, email_type|
    begin
      next unless ::DigestPostback.enabled?
      next unless email_type.to_s == "digest"

      # Enqueue fire-and-forget
      Jobs.enqueue(:digest_postback)

      # Optional extra log (enqueue success)
      ::DigestPostback.log("Enqueued digest postback job")
    rescue StandardError => e
      # Must NEVER affect digest flow
      ::DigestPostback.log_error("ENQUEUE ERROR err=#{e.class}: #{e.message}")
    end
  end
end
