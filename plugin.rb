# frozen_string_literal: true

# name: digest-report-simple
# about: Fail-safe POST of a 20-digit email_id after each delivered digest email
# version: 1.0
# authors: you

after_initialize do
  require "net/http"
  require "uri"
  require "securerandom"

  # ===== CONFIG =====
  DIGEST_REPORT_ENABLED = true
  DIGEST_REPORT_URL     = "https://ai.templetrends.com/digest_report.php"

  OPEN_TIMEOUT_SECONDS  = 2
  READ_TIMEOUT_SECONDS  = 2

  # ===== Helpers =====
  module ::DigestReportSimple
    def self.random_20_digit_id
      # 0..(10^20-1) padded to 20 digits
      format("%020d", SecureRandom.random_number(10**20))
    end

    def self.post_email_id(url, email_id, open_timeout, read_timeout)
      return if url.to_s.strip.empty?

      uri = URI.parse(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (uri.scheme == "https")
      http.open_timeout = open_timeout.to_i if open_timeout.to_i > 0
      http.read_timeout = read_timeout.to_i if read_timeout.to_i > 0

      req = Net::HTTP::Post.new(uri.request_uri)
      req["Content-Type"] = "application/x-www-form-urlencoded"
      req.body = "email_id=#{URI.encode_www_form_component(email_id)}"

      res = http.request(req)

      unless res.is_a?(Net::HTTPSuccess)
        Rails.logger.warn("[digest-report-simple] HTTP #{res.code} from endpoint")
      end
    rescue => e
      Rails.logger.warn("[digest-report-simple] POST failed: #{e.class}: #{e.message}")
    end
  end

  # ===== Subscribe to digest deliveries =====
  ActiveSupport::Notifications.subscribe("deliver.action_mailer") do |*args|
    begin
      next unless DIGEST_REPORT_ENABLED

      event   = ActiveSupport::Notifications::Event.new(*args)
      payload = event.payload || {}

      next unless payload[:mailer].to_s == "UserNotifications"
      next unless payload[:action].to_s == "digest"

      email_id = ::DigestReportSimple.random_20_digit_id

      ::DigestReportSimple.post_email_id(
        DIGEST_REPORT_URL,
        email_id,
        OPEN_TIMEOUT_SECONDS,
        READ_TIMEOUT_SECONDS
      )
    rescue => e
      # Absolute fail-safe: NEVER allow reporting to break digest delivery
      Rails.logger.error("[digest-report-simple] subscriber crashed: #{e.class}: #{e.message}")
    end
  end
end
