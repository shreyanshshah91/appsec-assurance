# Ruby / Rails

**Detector keys:** `ruby`, `rails`, `graphql` (graphql-ruby)

## Untrusted input sources

- `params` (merged path, query and body; nested hashes/arrays), `request.headers`, `request.env`, `cookies` (unsigned unless `.signed`/`.encrypted`), `request.raw_post`, `request.body`, uploaded `ActionDispatch::Http::UploadedFile#original_filename`, `request.host`/`request.referer`.
- ActionCable channel `data`, ActiveJob/Sidekiq job arguments (Redis access = job injection), GraphQL resolver args, ActionMailbox inbound mail, webhooks, Rake task `ENV` args.
- Sinatra/Hanami/Roda: `params`, `request` similarly.

## Dangerous sinks

| Sink | Vulnerability class | CWE | Safe alternative |
|------|--------------------|-----|------------------|
| `where("name = '#{x}'")`, `find_by_sql("...#{x}")`, `order(params[:sort])`, `pluck(x)`, `group`, `having`, `select`, `joins("...#{x}")`, `exists?(params[:id])` (hash form), `calculate` | SQL injection | CWE-89 | `where(name: x)`, `where("name = ?", x)`, `sanitize_sql_*`, allowlisted sort columns |
| `connection.execute("...#{x}")`, `Arel.sql(x)` | SQL injection | CWE-89 | `exec_query` with binds; never wrap input in `Arel.sql` |
| `system("cmd #{x}")`, backticks, `%x()`, `exec`, `spawn`, `IO.popen(str)`, `Open3.*(str)` | OS command injection | CWE-78 | Array form: `system("cmd", x)`; `Open3.capture2("cmd", x)` |
| `Kernel#open(x)`, `URI.open(x)`, `IO.read(x)` with `|` prefix | Command injection / SSRF | CWE-78, CWE-918 | `File.open`; `Net::HTTP` with host allowlist |
| `eval`, `instance_eval`, `class_eval` (string), `binding.eval` | Code injection | CWE-95 | Avoid; explicit dispatch |
| `send(params[:m])`, `public_send(x)`, `constantize`, `safe_constantize`, `Object.const_get(x)` | Unsafe reflection | CWE-470 | Allowlist hash of method/class names |
| `Marshal.load`, `YAML.load` (Psych < 4 = unsafe), `YAML.unsafe_load`, `Oj.load` (object mode) | Unsafe deserialization | CWE-502 | `YAML.safe_load(permitted_classes: [...])`, `JSON.parse` |
| `raw(x)`, `x.html_safe`, `<%== x %>`, `content_tag` with `html_safe` children, `render inline: x` | XSS (and SSTI for `inline:`) | CWE-79, CWE-1336 | `<%= %>` autoescape; `sanitize(x, tags: [...])` |
| `link_to x, params[:url]` / `href` from input | XSS via `javascript:` | CWE-79 | Validate scheme |
| `render params[:template]`, `render file: x` | LFI / template injection | CWE-22, CWE-98 | Fixed template names |
| `send_file(params[:path])`, `File.join(base, x)` | Path traversal | CWE-22 | `File.expand_path` + prefix check; ActiveStorage |
| `redirect_to params[:return_to]` | Open redirect | CWE-601 | `redirect_to url_from(params[:return_to]) || root_path` (Rails 7+); `allow_other_host: false` |
| `Model.new(params[:user])` / `update(params[:user])` without permit | Mass assignment | CWE-915 | `params.require(:user).permit(:name, :email)` |
| `Nokogiri::XML(x) { \|c\| c.noent }`, `REXML` on old versions | XXE / entity expansion | CWE-611, CWE-776 | Nokogiri defaults (`NONET`, no `NOENT`) |
| `rand`, `Random.new` for tokens | Weak PRNG | CWE-338 | `SecureRandom.urlsafe_base64` |
| `==` on tokens | Timing attack | CWE-208 | `ActiveSupport::SecurityUtils.secure_compare` |
| `Regexp.new(params[:q])`, `^`/`$` in validations | ReDoS / validation bypass | CWE-1333, CWE-185 | `Regexp.escape`; use `\A`/`\z` |

## Framework pitfalls and insecure defaults

- **Strong parameters:** `params.permit!`, `permit(:role, :admin, :account_id)`, nested `permit(settings: {})` (allows arbitrary keys); `to_unsafe_h`; `accepts_nested_attributes_for` exposing child records of other users.
- **CSRF:** `ApplicationController` should not use `skip_forgery_protection` or `protect_from_forgery with: :null_session` for cookie-auth HTML endpoints; API-only controllers inheriting `ActionController::API` have no CSRF — they must not accept cookie sessions. `skip_before_action :verify_authenticity_token` on any state-changing action needs a justification. GET routes that change state (`get "/delete"`) bypass CSRF entirely.
- **Validation regexes** using `^...$` match per line — use `\A...\z` (Rails `format:` raises on multiline anchors unless `multiline: true`).
- **Secrets:** `config/master.key` or `config/credentials/*.key` committed; `secret_key_base` in repo → cookie forgery and, with Marshal cookie serializer (`cookies_serializer = :marshal`/`:hybrid`), RCE.
- **Production config:** `config.consider_all_requests_local = true`, `config.force_ssl = false`, `config.hosts` empty (Host header attacks against password-reset URLs; set `default_url_options` explicitly), web-console gem in production, `config.action_dispatch.default_headers` weakened, `content_security_policy` absent.
- **ActiveStorage:** public service URLs, proxy mode exposing all blobs, content-type trust for previews (ImageMagick/libvips CVEs); `variant` params from users.
- **Sidekiq Web UI** mounted without auth constraint (`mount Sidekiq::Web` outside `authenticate :user, ->(u){u.admin?}`).
- **Callbacks** (`before_action`) — `only:`/`except:` lists that miss new actions; `skip_before_action :authenticate_user!` copied into subclasses.
- **Gems:** `Gemfile` sources other than rubygems.org, `git:` gems unpinned, native-extension gems running `extconf.rb` at install.

## Authn/authz idioms to verify

- Devise: `before_action :authenticate_user!` at `ApplicationController` level; `devise :lockable, :timeoutable, :confirmable` as appropriate; `config.paranoid = true` against user enumeration; `config.stretches`.
- Pundit: `after_action :verify_authorized` / `verify_policy_scoped`; every action calls `authorize record`; `policy_scope(Model)` for index; policies don't default `true`.
- CanCanCan: `load_and_authorize_resource`; `check_authorization`; `can :manage, :all` grants.
- Scoping: `current_user.documents.find(params[:id])` rather than `Document.find(params[:id])`; multi-tenancy gems (acts_as_tenant) set from session, not params.
- `has_secure_password` (bcrypt), password reset tokens via `generates_token_for` / `signed_id(expires_in:, purpose:)`.

## Useful grep patterns

```bash
rg -n --type ruby '(where|order|group|having|joins|pluck|select|find_by_sql|exists\?|execute)\(\s*["\x27][^"\x27]*#\{'
rg -n --type ruby '\.order\(\s*params|Arel\.sql\(|sanitize_sql\('
rg -n --type ruby '\bsystem\(|`[^`]*#\{|%x\(|\bexec\(|IO\.popen|Open3\.|\bspawn\(|(?:\b|URI\.)open\('
rg -n --type ruby '\beval\(|instance_eval|class_eval\s*\(?\s*["\x27]|\.(send|public_send)\(\s*params|constantize|const_get\('
rg -n --type ruby 'Marshal\.load|YAML\.(load|unsafe_load)\b|Oj\.load'
rg -n '\.html_safe|\braw\(|<%==|render\s+(inline|file):' -g '*.{rb,erb,haml,slim}'
rg -n --type ruby 'permit!|to_unsafe_h|skip_forgery_protection|verify_authenticity_token|null_session'
rg -n --type ruby 'redirect_to\s+params|send_file\s*\(?\s*params'
rg -n --type ruby 'validates.*format:.*/\^|consider_all_requests_local\s*=\s*true|force_ssl\s*=\s*false'
rg -n --type ruby 'mount Sidekiq::Web|SecureRandom|\brand\('
```

## Recommended tools

- Brakeman (`brakeman -f sarif -o brakeman.sarif`), bundler-audit (`bundle audit check --update`), Semgrep (`p/ruby`, `p/rails`), RuboCop with `rubocop-rails` security cops, OSV-Scanner (`Gemfile.lock`), Gitleaks.

## Secure code patterns

```ruby
# Vulnerable: SQLi
User.where("email = '#{params[:email]}'")
User.order(params[:sort])
# Fixed
User.where(email: params[:email])
User.order(%w[name created_at].include?(params[:sort]) ? params[:sort] : "created_at")

# Vulnerable: mass assignment
@user.update(params[:user])
# Fixed
@user.update(params.require(:user).permit(:name, :email))

# Vulnerable: IDOR
@doc = Document.find(params[:id])
# Fixed
@doc = current_user.documents.find(params[:id])   # or authorize @doc (Pundit)

# Vulnerable: XSS
<%= raw comment.body %>
# Fixed
<%= sanitize comment.body, tags: %w[b i a p], attributes: %w[href] %>

# Vulnerable: unsafe reflection / command
params[:type].constantize.new ; system("convert #{file} out.png")
# Fixed
{ "pdf" => PdfExport, "csv" => CsvExport }.fetch(params[:type]).new ; system("convert", file, "out.png")
```
