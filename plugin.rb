# name: digest-report
# about: POST to external endpoint after digest email is sent (failsafe, async) + optional open tracking pixel
# version: 1.1
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

    ENDPOINT_URL = "https://ai.templetrends.com/digest_report.php" # postback after send

    # ===== Open tracking switch =====
    OPEN_TRACKING_ENABLED = true

    # Tracking pixel endpoint (must return an actual tiny image)
    # Example: https://ai.templetrends.com/digest_open.php?email_id=...&user_id=...&user_email=...
    OPEN_TRACKING_PIXEL_BASE_URL = "https://ai.templetrends.com/digest_open.php"

    # POST field names
    EMAIL_ID_FIELD              = "email_id"            # 20-digit random
    OPEN_TRACKING_USED_FIELD    = "open_tracking_used"  # "1" or "0"

    TOPIC_IDS_FIELD             = "topic_ids"           # CSV in EMAIL ORDER
    TOPIC_COUNT_FIELD           = "topic_ids_count"     # integer
    FIRST_TOPIC_ID_FIELD        = "first_topic_id"      # first topic id in email order (string)

    SUBJECT_FIELD               = "subject"
    SUBJECT_PRESENT_FLD         = "subject_present"

    FROM_EMAIL_FIELD            = "from_email"

    USER_ID_FIELD               = "user_id"
    USERNAME_FIELD              = "username"
    USER_CREATED_AT_FIELD       = "user_created_at_utc" # ISO8601

    # keep strings sane
    SUBJECT_MAX_LEN  = 300
    FROM_MAX_LEN     = 200
    USERNAME_MAX_LEN = 200

    # Timeouts
    OPEN_TIMEOUT_SECONDS  = 3
    READ_TIMEOUT_SECONDS  = 3
    WRITE_TIMEOUT_SECONDS = 3

    # Sidekiq retry count
    JOB_RETRY_COUNT = 2
    # =========================

    # PluginStore keys
    STORE_NAMESPACE = PLUGIN_NAME
    def self.store_key_last_email_id(user_id)
      "last_email_id_user_#{user_id}"
    end

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

    def self.open_tracking_enabled?
      return false unless OPEN_TRACKING_ENABLED
      return false if OPEN_TRACKING_PIXEL_BASE_URL.to_s.strip.empty?
      true
    rescue StandardError
      false
    end

    def self.safe_str(v, max_len)
      s = v.to_s.strip
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
    def self.random_20_digit_id
      digits = +""
      20.times { digits << SecureRandom.random_number(10).to_s }
      digits
    rescue StandardError
      t = (Time.now.to_f * 1000).to_i.to_s
      (t + "0" * 20)[0, 20]
    end

    def self.store_last_email_id_for_user(user_id, email_id)
      return if user_id.to_i <= 0
      return if email_id.to_s.strip.empty?
      PluginStore.set(STORE_NAMESPACE, store_key_last_email_id(user_id.to_i), email_id.to_s.strip)
      true
    rescue StandardError
      false
    end

    def self.get_last_email_id_for_user(user_id)
      return "" if user_id.to_i <= 0
      v = PluginStore.get(STORE_NAMESPACE, store_key_last_email_id(user_id.to_i))
      v.to_s.strip
    rescue StandardError
      ""
    end

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
        message.body&.decoded.to_s
      rescue StandardError
        ""
      end
    end

    # Extract topic IDs in FIRST-SEEN ORDER in the email.
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

        uri = (URI.parse(u) rescue nil)
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

    # Build tracking pixel HTML (safe, tiny, hidden)
    def self.build_tracking_pixel_html(email_id:, user_id:, user_email:)
      base = OPEN_TRACKING_PIXEL_BASE_URL.to_s.strip
      return "" if base.empty?

      q = {
        "email_id"   => email_id.to_s,
        "user_id"    => user_id.to_s,
        "user_email" => user_email.to_s
      }

      url =
        begin
          uri = URI.parse(base)
          existing = uri.query.to_s
          add = URI.encode_www_form(q)
          uri.query = existing.empty? ? add : "#{existing}&#{add}"
          uri.to_s
        rescue StandardError
          "#{base}?#{URI.encode_www_form(q)}"
        end

      %Q(<img src="#{CGI.escapeHTML(url)}" width="1" height="1" style="display:none!important;max-height:0;overflow:hidden" alt="" />)
    rescue StandardError
      ""
    end
  end

  # =========================
  # Inject tracking pixel BEFORE send (digest only)
  # =========================
  module ::DigestReportEmailBuilderPatch
    def html_part
      part = super
      begin
        return part unless ::DigestReport.enabled?
        return part unless ::DigestReport.open_tracking_enabled?

        # Only digests
        typ = ""
        begin
          typ = (@opts && @opts[:type]).to_s
        rescue StandardError
          typ = ""
        end
        return part unless typ == "digest"

        # Identify recipient + user
        user_email = ""
        begin
          user_email = @to.to_s.strip
        rescue StandardError
          user_email = ""
        end

        user = nil
        begin
          user = @opts[:user] if @opts.is_a?(Hash)
        rescue StandardError
          user = nil
        end
        if user.nil?
          begin
            uid = (@opts && @opts[:user_id]).to_i
            user = User.find_by(id: uid) if uid > 0
          rescue StandardError
            user = nil
          end
        end
        return part if user.nil? # can't store / can't do per-user

        # Generate email_id ONCE per message build
        @digest_report_email_id ||= ::DigestReport.random_20_digit_id

        # Store last email_id per user (server-side "bubble")
        ::DigestReport.store_last_email_id_for_user(user.id, @digest_report_email_id)

        # Only if HTML exists
        html = ""
        begin
          html = part&.body&.decoded.to_s
        rescue StandardError
          html = ""
        end
        return part if html.to_s.empty?

        pixel = ::DigestReport.build_tracking_pixel_html(
          email_id: @digest_report_email_id,
          user_id: user.id,
          user_email: user_email
        )
        return part if pixel.to_s.empty?

        # Inject before </body> if present, else append
        new_html =
          if html.include?("</body>")
            html.sub("</body>", "#{pixel}</body>")
          else
            html + pixel
          end

        begin
          part.body = new_html
        rescue StandardError
          return part
        end

        ::DigestReport.log("OpenTracking injected email_id=#{@digest_report_email_id} user_id=#{user.id}")
        part
      rescue StandardError => e
        ::DigestReport.log_error("OpenTracking inject error err=#{e.class}: #{e.message}")
        part
      end
    end
  end

  begin
    Email::MessageBuilder.prepend(::DigestReportEmailBuilderPatch)
  rescue StandardError => e
    ::DigestReport.log_error("Failed to prepend EmailBuilderPatch err=#{e.class}: #{e.message}")
  end

  # =========================
  # Postback job (includes open_tracking_used flag)
  # =========================
  class ::Jobs::DigestReportPostback < ::Jobs::Base
    sidekiq_options queue: "low", retry: ::DigestReport::JOB_RETRY_COUNT

    def execute(args)
      begin
        return unless ::DigestReport.enabled?

        url = ::DigestReport::ENDPOINT_URL.to_s.strip

        email_id = args[:email_id].to_s.strip
        email_id = ::DigestReport.random_20_digit_id if email_id.empty?

        open_tracking_used = args[:open_tracking_used].to_s.strip
        open_tracking_used = "0" unless open_tracking_used == "1"

        user_email = args[:user_email].to_s.strip
        ::DigestReport.log_error("Missing user_email in job args; sending anyway with blank user_email") if user_email.empty?

        subject = ::DigestReport.safe_str(args[:subject], ::DigestReport::SUBJECT_MAX_LEN)
        subject_present = subject.empty? ? "0" : "1"

        from_email = ::DigestReport.safe_str(args[:from_email], ::DigestReport::FROM_MAX_LEN)

        user_id  = args[:user_id].to_s
        username = ::DigestReport.safe_str(args[:username], ::DigestReport::USERNAME_MAX_LEN)
        user_created_at_utc = args[:user_created_at_utc].to_s

        # topic IDs in email order (dedupe while keeping order)
        incoming_ids = Array(args[:topic_ids]).map { |x| x.to_i }
        seen = {}
        topic_ids_ordered = []
        incoming_ids.each do |tid|
          next if tid <= 0
          next if seen[tid]
          seen[tid] = true
          topic_ids_ordered << tid
        end

        topic_ids_csv   = topic_ids_ordered.join(",")
        topic_ids_count = topic_ids_ordered.length
        first_topic_id  = topic_ids_ordered[0] ? topic_ids_ordered[0].to_s : ""

        uri = (URI.parse(url) rescue nil)
        if uri.nil?
          ::DigestReport.log_error("Invalid ENDPOINT_URL #{url.inspect}")
          return
        end

        unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
          ::DigestReport.log_error("Invalid ENDPOINT_URL scheme (must be http/https): #{url.inspect}")
          return
        end

        form_kv = [
          [::DigestReport::EMAIL_ID_FIELD, email_id],
          [::DigestReport::OPEN_TRACKING_USED_FIELD, open_tracking_used],
          ["user_email", user_email],

          [::DigestReport::FROM_EMAIL_FIELD, from_email],

          [::DigestReport::USER_ID_FIELD, user_id],
          [::DigestReport::USERNAME_FIELD, username],
          [::DigestReport::USER_CREATED_AT_FIELD, user_created_at_utc],

          [::DigestReport::SUBJECT_FIELD, subject],
          [::DigestReport::SUBJECT_PRESENT_FLD, subject_present],

          [::DigestReport::TOPIC_IDS_FIELD, topic_ids_csv],
          [::DigestReport::TOPIC_COUNT_FIELD, topic_ids_count.to_s],
          [::DigestReport::FIRST_TOPIC_ID_FIELD, first_topic_id]
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
            ::DigestReport.log("POST OK code=#{res.code} ms=#{ms} email_id=#{email_id} open_tracking_used=#{open_tracking_used} topic_ids_count=#{topic_ids_count} first_topic_id=#{first_topic_id}")
          else
            ::DigestReport.log_error("POST FAIL code=#{res.code} ms=#{ms} email_id=#{email_id} open_tracking_used=#{open_tracking_used} topic_ids_count=#{topic_ids_count} body=#{res.body.to_s[0, 500].inspect}")
          end
        rescue StandardError => e
          ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round
          ::DigestReport.log_error("POST ERROR ms=#{ms} email_id=#{email_id} open_tracking_used=#{open_tracking_used} topic_ids_count=#{topic_ids_count} err=#{e.class}: #{e.message}")
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

  # =========================
  # After email send: enqueue postback (uses stored email_id if open-tracking path was used)
  # =========================
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

      user = nil
      begin
        user = User.find_by_email(recipient) unless recipient.empty?
      rescue StandardError
        user = nil
      end

      user_id = user ? user.id : ""
      username = user ? user.username.to_s : ""
      user_created_at_utc = user ? ::DigestReport.safe_iso8601(user.created_at) : ""

      topic_ids = ::DigestReport.extract_topic_ids_from_message(message)

      # Use pre-send stored id if open tracking was actually used
      email_id = ""
      open_tracking_used = "0"

      if ::DigestReport.open_tracking_enabled? && user
        stored = ::DigestReport.get_last_email_id_for_user(user.id)
        if !stored.to_s.strip.empty?
          email_id = stored
          open_tracking_used = "1"
        end
      end

      email_id = ::DigestReport.random_20_digit_id if email_id.to_s.strip.empty?

      Jobs.enqueue(
        :digest_report_postback,
        email_id: email_id,
        open_tracking_used: open_tracking_used,
        user_email: recipient,
        from_email: from_email,
        user_id: user_id,
        username: username,
        user_created_at_utc: user_created_at_utc,
        subject: subject,
        topic_ids: topic_ids
      )

      first_topic_id = topic_ids[0] ? topic_ids[0].to_s : ""
      ::DigestReport.log("Enqueued postback email_id=#{email_id} open_tracking_used=#{open_tracking_used} user_found=#{!user.nil?} topic_ids_count=#{topic_ids.length} first_topic_id=#{first_topic_id}")
    rescue StandardError => e
      ::DigestReport.log_error("ENQUEUE ERROR err=#{e.class}: #{e.message}")
    end
  end
end
