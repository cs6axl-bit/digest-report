# name: digest-report
# about: POST to external endpoint after digest email is sent (failsafe, async)
# version: 0.8
# authors: you

after_initialize do
  require "net/http"
  require "uri"
  require "cgi"
  require "time"
  require "securerandom"

  module ::DigestReport
    PLUGIN_NAME = "digest-report"

    # =========================
    # HARD-CODED SETTINGS (edit here)
    # =========================
    ENABLED = true

    ENDPOINT_URL = "https://ai.templetrends.com/digest_report.php" # <-- change

    # POST field names
    EMAIL_ID_FIELD         = "email_id"            # 20-digit random
    TOPIC_IDS_FIELD         = "topic_ids"          # CSV in EMAIL ORDER: "12,45,99"
    TOPIC_COUNT_FIELD       = "topic_ids_count"    # integer

    SUBJECT_FIELD           = "subject"            # string
    SUBJECT_PRESENT_FLD     = "subject_present"    # "1"/"0"

    FROM_EMAIL_FIELD        = "from_email"         # string

    USER_ID_FIELD           = "user_id"            # integer/string
    USERNAME_FIELD          = "username"           # string
    USER_CREATED_AT_FIELD   = "user_created_at_utc"# ISO8601

    # keep strings sane
    SUBJECT_MAX_LEN  = 300
    FROM_MAX_LEN     = 200
    USERNAME_MAX_LEN = 200

    # Timeouts (keep short so jobs can't hang workers too long)
    OPEN_TIMEOUT_SECONDS  = 3
    READ_TIMEOUT_SECONDS  = 3
    WRITE_TIMEOUT_SECONDS = 3

    # Sidekiq retry count (small, so failures don't pile up)
    JOB_RETRY_COUNT = 2
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

    def self.safe_str(v, max_len)
      s = v.to_s
      s = s.strip
      s = s[0, max_len] if s.length > max_len
      s
    rescue StandardError
      ""
    end

    def self.safe_iso8601(t)
      return "" if t.nil?
      begin
        tt = t.respond_to?(:utc) ? t.utc : t
        tt.iso8601
      rescue StandardError
        ""
      end
    end

    # Generate a random 20-digit numeric string.
    # Uses SecureRandom for entropy, then maps to digits.
    def self.random_20_digit_id
      # 10 bytes -> 20 hex chars, but we want digits only.
      # We'll generate 20 digits directly using SecureRandom.random_number.
      digits = +""
      20.times { digits << SecureRandom.random_number(10).to_s }
      digits
    rescue StandardError
      # fallback: time-based (still 20 digits), but should almost never happen
      t = (Time.now.to_f * 1000).to_i.to_s # ms since epoch
      (t + "0" * 20)[0, 20]
    end

    # Prefer HTML part, fallback to text, fallback to whole body
    def self.extract_email_body(message)
      return "" if message.nil?

      if message.respond_to?(:multipart?) && message.multipart?
        html = ""
        txt  = ""
        begin
          html = message.html_part&.body&.decoded.to_s
        rescue StandardError
          html = ""
        end
        begin
          txt = message.text_part&.body&.decoded.to_s
        rescue StandardError
          txt = ""
        end
        return html unless html.to_s.empty?
        return txt  unless txt.to_s.empty?
      end

      begin
        return message.body&.decoded.to_s
      rescue StandardError
        ""
      end
    end

    # Extract unique topic IDs from URLs in the email, PRESERVING FIRST-SEEN ORDER
    def self.extract_topic_ids_from_message(message)
      body = extract_email_body(message)
      return [] if body.to_s.empty?

      begin
        body = CGI.unescapeHTML(body.to_s)
      rescue StandardError
        body = body.to_s
      end

      urls =
        begin
          body.scan(%r{https?://[^\s"'<>()]+}i)
        rescue StandardError
          []
        end

      ids = []
      seen = {}

      urls.each do |raw|
        next if raw.to_s.empty?

        u = raw.to_s.gsub(/[)\].,;]+$/, "")

        uri =
          begin
            URI.parse(u)
          rescue StandardError
            nil
          end
        next if uri.nil?

        path = uri.path.to_s
        next if path.empty?

        m = path.match(%r{/t/(?:[^/]+/)?(\d+)(?:/|$)}i)
        next if m.nil?

        tid = m[1].to_i
        next if tid <= 0
        next if seen[tid]

        seen[tid] = true
        ids << tid
      end

      ids
    rescue StandardError => e
      ::DigestReport.log_error("extract_topic_ids_from_message error err=#{e.class}: #{e.message}")
      []
    end
  end

  class ::Jobs::DigestReportPostback < ::Jobs::Base
    sidekiq_options queue: "low", retry: ::DigestReport::JOB_RETRY_COUNT

    def execute(args)
      begin
        return unless ::DigestReport.enabled?

        url = ::DigestReport::ENDPOINT_URL.to_s.strip

        # email_id is generated at enqueue-time so it's tied to this email send
        email_id = args[:email_id].to_s.strip
        if email_id.empty?
          email_id = ::DigestReport.random_20_digit_id
        end

        user_email = args[:user_email].to_s.strip
        if user_email.empty?
          ::DigestReport.log_error("Missing user_email in job args; sending anyway with blank user_email")
        end

        # subject
        subject = ::DigestReport.safe_str(args[:subject], ::DigestReport::SUBJECT_MAX_LEN)
        subject_present = (!subject.empty?) ? "1" : "0"

        # from
        from_email = ::DigestReport.safe_str(args[:from_email], ::DigestReport::FROM_MAX_LEN)

        # user info
        user_id   = args[:user_id].to_s
        username  = ::DigestReport.safe_str(args[:username], ::DigestReport::USERNAME_MAX_LEN)
        user_created_at_utc = args[:user_created_at_utc].to_s

        # topic IDs CSV (EMAIL ORDER)
        topic_ids = Array(args[:topic_ids]).map { |x| x.to_i }
        seen = {}
        topic_ids_ordered = []
        topic_ids.each do |tid|
          next if tid <= 0
          next if seen[tid]
          seen[tid] = true
          topic_ids_ordered << tid
        end

        topic_ids_csv   = topic_ids_ordered.join(",")
        topic_ids_count = topic_ids_ordered.length

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

        form_kv = [
          [::DigestReport::EMAIL_ID_FIELD, email_id],
          ["user_email", user_email],

          [::DigestReport::FROM_EMAIL_FIELD, from_email],

          [::DigestReport::USER_ID_FIELD, user_id],
          [::DigestReport::USERNAME_FIELD, username],
          [::DigestReport::USER_CREATED_AT_FIELD, user_created_at_utc],

          [::DigestReport::SUBJECT_FIELD, subject],
          [::DigestReport::SUBJECT_PRESENT_FLD, subject_present],

          [::DigestReport::TOPIC_IDS_FIELD, topic_ids_csv],
          [::DigestReport::TOPIC_COUNT_FIELD, topic_ids_count.to_s]
        ]

        body = URI.encode_www_form(form_kv)

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
            ::DigestReport.log(
              "POST OK code=#{res.code} ms=#{ms} email_id=#{email_id} user_email_present=#{!user_email.empty?} subject_present=#{subject_present} topic_ids_count=#{topic_ids_count} user_id_present=#{!user_id.empty?}"
            )
          else
            ::DigestReport.log_error(
              "POST FAIL code=#{res.code} ms=#{ms} email_id=#{email_id} user_email_present=#{!user_email.empty?} topic_ids_count=#{topic_ids_count} body=#{res.body.to_s[0, 500].inspect}"
            )
          end
        rescue StandardError => e
          ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round
          ::DigestReport.log_error(
            "POST ERROR ms=#{ms} email_id=#{email_id} user_email_present=#{!user_email.empty?} topic_ids_count=#{topic_ids_count} err=#{e.class}: #{e.message}"
          )
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

      subject =
        begin
          ::DigestReport.safe_str(message&.subject, ::DigestReport::SUBJECT_MAX_LEN)
        rescue StandardError
          ""
        end

      from_email =
        begin
          Array(message&.from).first.to_s.strip
        rescue StandardError
          ""
        end

      # Lookup user by recipient email
      user = nil
      begin
        user = User.find_by_email(recipient) unless recipient.empty?
      rescue StandardError
        user = nil
      end

      user_id = user ? user.id : ""
      username = user ? user.username.to_s : ""
      user_created_at_utc = user ? ::DigestReport.safe_iso8601(user.created_at) : ""

      # Topic IDs in EMAIL ORDER
      topic_ids = ::DigestReport.extract_topic_ids_from_message(message)

      # Generate a per-email 20-digit id at enqueue-time
      email_id = ::DigestReport.random_20_digit_id

      Jobs.enqueue(
        :digest_report_postback,
        email_id: email_id,
        user_email: recipient,
        from_email: from_email,
        user_id: user_id,
        username: username,
        user_created_at_utc: user_created_at_utc,
        subject: subject,
        topic_ids: topic_ids
      )

      ::DigestReport.log(
        "Enqueued postback email_id=#{email_id} user_email_present=#{!recipient.empty?} from_present=#{!from_email.empty?} user_found=#{!user.nil?} topic_ids_count=#{topic_ids.length}"
      )
    rescue StandardError => e
      ::DigestReport.log_error("ENQUEUE ERROR err=#{e.class}: #{e.message}")
    end
  end
end
