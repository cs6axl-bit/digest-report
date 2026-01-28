# frozen_string_literal: true

# name: digest-report
# about: POST a JSON report to an external endpoint after each delivered digest email
# version: 1.3
# authors: you
# url: https://github.com/YOURORG/digest-report

after_initialize do
  require "net/http"
  require "uri"
  require "json"
  require "securerandom"
  require "time"

  # ==========================================================
  # CONFIG (edit these constants)
  # ==========================================================
  DIGEST_REPORT_ENABLED       = true
  DIGEST_REPORT_ENDPOINT_URL  = "https://ai.templetrends.com/digest_report.php"
  DIGEST_REPORT_SECRET        = "wef345345345jweflfijl"

  DIGEST_REPORT_INCLUDE_HTML  = false # if true, sends full HTML of digest
  OPEN_TIMEOUT_SECONDS        = 3
  READ_TIMEOUT_SECONDS        = 5

  # stores per-user digest count in a custom field
  USER_FIELD_DIGEST_COUNT     = "digest_report_received_count"

  # NEW: SMTP response capture switch
  CAPTURE_SMTP_RESPONSE       = false  # << set true if you want best-effort SMTP response

  # ==========================================================
  # SMTP response capture (best-effort, SMTP only) - optional
  # ==========================================================
  module ::DigestReportSmtpCapture
    THREAD_KEY = :digest_report_last_smtp_response

    def deliver!(mail)
      response = start_smtp_session do |smtp|
        Mail::SMTPConnection
          .new(connection: smtp, return_response: true)
          .deliver!(mail)
      end

      Thread.current[THREAD_KEY] = begin
        if response.respond_to?(:status) || response.respond_to?(:string)
          {
            status: (response.respond_to?(:status) ? response.status : nil),
            string: (response.respond_to?(:string) ? response.string : response.to_s)
          }
        else
          { string: response.to_s }
        end
      rescue
        { string: response.to_s }
      end

      settings[:return_response] ? response : self
    end
  end

  if CAPTURE_SMTP_RESPONSE
    begin
      if defined?(Mail::SMTP)
        Mail::SMTP.prepend(::DigestReportSmtpCapture)
        Rails.logger.info("[digest-report] SMTP response capture enabled")
      else
        Rails.logger.warn("[digest-report] SMTP capture enabled but Mail::SMTP not defined")
      end
    rescue => e
      Rails.logger.warn("[digest-report] SMTP patch failed: #{e.class}: #{e.message}")
    end
  else
    Rails.logger.info("[digest-report] SMTP response capture disabled")
  end

  # ==========================================================
  # Helpers
  # ==========================================================
  module ::DigestReport
    def self.random_20_digit_id
      format("%020d", SecureRandom.random_number(10**20))
    end

    def self.safe_parse_json_array(str)
      return [] if str.nil? || str.to_s.strip.empty?
      arr = JSON.parse(str) rescue []
      arr.is_a?(Array) ? arr : []
    end

    def self.increment_digest_count_for(user, field_key)
      cur = (user.custom_fields[field_key]).to_i
      cur += 1
      user.custom_fields[field_key] = cur.to_s
      user.save_custom_fields(true)
      cur
    rescue => e
      Rails.logger.warn("[digest-report] digest count increment failed user_id=#{user&.id}: #{e.class}: #{e.message}")
      0
    end

    def self.consume_smtp_response
      # If SMTP capture is off, just return nil without touching Thread.current
      return nil unless defined?(::DigestReportSmtpCapture)

      v = Thread.current[::DigestReportSmtpCapture::THREAD_KEY] rescue nil
      Thread.current[::DigestReportSmtpCapture::THREAD_KEY] = nil rescue nil
      v
    rescue
      nil
    end

    def self.post_json(endpoint, secret, payload, open_timeout, read_timeout)
      return if endpoint.to_s.strip.empty?

      uri = URI.parse(endpoint)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (uri.scheme == "https")
      http.open_timeout = open_timeout if open_timeout.to_i > 0
      http.read_timeout = read_timeout if read_timeout.to_i > 0

      req = Net::HTTP::Post.new(uri.request_uri)
      req["Content-Type"] = "application/json"
      req["X-Digest-Report-Secret"] = secret unless secret.to_s.empty?
      req.body = JSON.generate(payload)

      res = http.request(req)
      unless res.is_a?(Net::HTTPSuccess)
        Rails.logger.warn("[digest-report] endpoint HTTP #{res.code}: #{res.body.to_s[0, 500]}")
      end
    rescue => e
      Rails.logger.warn("[digest-report] POST failed: #{e.class}: #{e.message}")
    end
  end

  # ==========================================================
  # Patch digest builder to attach topic IDs to headers
  # ==========================================================
  module ::DigestReportDigestHeaderPatch
    def digest(user, opts = {})
      msg = super

      topic_ids = []
      begin
        instance_variables.each do |ivar|
          val = instance_variable_get(ivar)
          next unless val.is_a?(Array) && val.first

          val.each do |obj|
            topic_ids << obj.id if obj.respond_to?(:id) && obj.respond_to?(:title)
          end
        end
      rescue => e
        Rails.logger.warn("[digest-report] topic extraction failed user_id=#{user&.id}: #{e.class}: #{e.message}")
      end

      topic_ids.uniq!
      msg.header["X-Digest-Topic-Ids"] = JSON.generate(topic_ids)
      msg
    end
  end

  ::UserNotifications.prepend(::DigestReportDigestHeaderPatch)

  # ==========================================================
  # Subscribe to delivered emails for UserNotifications#digest
  # ==========================================================
  ActiveSupport::Notifications.subscribe("deliver.action_mailer") do |*args|
    next unless DIGEST_REPORT_ENABLED

    event = ActiveSupport::Notifications::Event.new(*args)
    payload = event.payload || {}

    next unless payload[:mailer].to_s == "UserNotifications"
    next unless payload[:action].to_s == "digest"

    message = payload[:message]
    next unless message

    # get user id from header (best-effort)
    user_id =
      begin
        hdr = message.header["X-Discourse-User-Id"]
        hdr ? hdr.to_s.to_i : nil
      rescue
        nil
      end

    user = (user_id && user_id > 0) ? User.find_by(id: user_id) : nil

    # smtp response (only if enabled)
    smtp_response = CAPTURE_SMTP_RESPONSE ? ::DigestReport.consume_smtp_response : nil

    # message headers
    to_email =
      begin
        arr = message.to
        arr.is_a?(Array) ? arr.join(",") : arr.to_s
      rescue
        nil
      end

    from_email =
      begin
        arr = message.from
        arr.is_a?(Array) ? arr.join(",") : arr.to_s
      rescue
        nil
      end

    subject_line =
      begin
        message.subject.to_s
      rescue
        nil
      end

    # topic ids included in digest (sent as "product_ids" per your requirement)
    topic_ids_json =
      begin
        message.header["X-Digest-Topic-Ids"].to_s
      rescue
        "[]"
      end
    topic_ids = ::DigestReport.safe_parse_json_array(topic_ids_json)

    digest_count = user ? ::DigestReport.increment_digest_count_for(user, USER_FIELD_DIGEST_COUNT) : 0

    html_body = nil
    if DIGEST_REPORT_INCLUDE_HTML
      html_body =
        begin
          if message.html_part
            message.html_part.body.to_s
          else
            message.body.to_s
          end
        rescue => e
          Rails.logger.warn("[digest-report] html extraction failed: #{e.class}: #{e.message}")
          nil
        end
    end

    out = {
      email_id: ::DigestReport.random_20_digit_id,
      sent_at_utc: Time.now.utc.iso8601,

      # user identifiers
      discourse_user_id: user&.id || user_id,
      discourse_username: user&.username,
      discourse_user_email: user&.email,
      discourse_user_created_at_utc: user&.created_at&.utc&.iso8601,

      digest_emails_received_to_date_count: digest_count,

      # email fields
      to_email: to_email,
      from_email: from_email,
      subject: subject_line,

      # smtp server response (optional)
      smtp_response: smtp_response,

      # requested name "product_ids" (contains topic ids)
      product_ids: topic_ids,

      include_html: DIGEST_REPORT_INCLUDE_HTML,
      html: html_body
    }

    ::DigestReport.post_json(
      DIGEST_REPORT_ENDPOINT_URL,
      DIGEST_REPORT_SECRET,
      out,
      OPEN_TIMEOUT_SECONDS,
      READ_TIMEOUT_SECONDS
    )
  end
end
