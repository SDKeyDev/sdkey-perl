# Sdkey

Official Perl client for [SDKey](https://docs.sdkey.dev) license authentication.

Implements the sealed session protocol: Ed25519-verified handshake, HKDF session keys, and AES-256-GCM validate envelopes, plus plaintext client auth (`register` / `login` / `upgrade`). See [PROTOCOL.md](./PROTOCOL.md).

## Install

```bash
cpanm Sdkey
# or from a checkout:
cpanm --installdeps .
perl Makefile.PL && make && make test
```

Requires Perl 5.16+ and [CryptX](https://metacpan.org/pod/CryptX).

## Quick start

Embed these values from the SDKey dashboard when you ship your app. `app_version` must **exactly match** the application version configured on the server (`clientVersion`); mismatch returns `APP_OUTDATED`.

```perl
use Sdkey;
use Sdkey::Error;

my $client = Sdkey->new(
  api_base_url       => 'https://api.sdkey.dev',
  app_id             => 'YOUR_APP_ID',
  app_version        => '1.0.0',
  app_public_key_b64 => 'YOUR_APP_PUBLIC_KEY_BASE64',
);

eval {
  # hwid is optional (omit for web clients — server skips HWID checks)
  my $result = $client->validate('SDKY-XXXX-XXXX-XXXX-XXXX', 'machine-hwid');
  if ($result->{success}) {
    print "licensed $result->{status} $result->{expires_at} $result->{subscription_tier}\n";
    print "message $result->{message}\n";
  } else {
    print "denied $result->{code} $result->{message}\n";
  }
  1;
} or do {
  my $err = $@;
  if (ref $err && $err->isa('Sdkey::Error')) {
    # Init / transport failures use `error` text from the server when present
    warn "[$err->{code}] $err->{message}\n";
  }
  die $err;
};
```

`validate` calls `init()` automatically when no session exists. Sessions last ~15 minutes server-side; on `SESSION_EXPIRED` the client clears local state so the next call re-handshakes.

### Client auth (plaintext JSON)

```perl
my $reg = $client->register(
  username    => 'player1',
  password    => '••••••••',
  license_key => 'SDKY-XXXX-XXXX-XXXX-XXXX',
  hwid        => 'machine-hwid',  # optional
);
if (!$reg->{success}) {
  print "$reg->{code} $reg->{error}\n";
} else {
  print "$reg->{session_token}\n";
}

my $login   = $client->login(username => 'player1', password => '••••••••');
my $upgrade = $client->upgrade(username => 'player1', license_key => 'SDKY-HIGHER-TIER-KEY');
```

`upgrade` takes **username + license key only** (no password). The new key’s `subscriptionTier` must be strictly greater than the user’s current tier.

## Where `message` vs `error` appears

Per-app `responseMessages` may customize many strings. The SDK surfaces whatever the server returns.

| Surface | Success text field | Failure text field |
|---|---|---|
| Session init | *(none)* | `error` (raised as `Sdkey::Error` message) |
| Sealed validate | `message` | `message` |
| Client register / login / upgrade | *(none)* | `error` on auth result |

### Example JSON shapes

**Init failure** (plaintext):

```json
{ "success": false, "error": "Client version outdated", "code": "APP_OUTDATED" }
```

**Sealed validate success** (`message`):

```json
{
  "success": true,
  "code": "OK",
  "message": "validated",
  "status": "active",
  "expiresAt": "2026-01-01T00:00:00.000Z",
  "subscriptionTier": 0,
  "sessionId": "...",
  "timestamp": 1720000001,
  "v": 1
}
```

**Sealed validate failure** (still `message`, not `error`):

```json
{
  "success": false,
  "code": "HWID_MISMATCH",
  "message": "Hardware ID mismatch",
  "status": null,
  "expiresAt": null,
  "sessionId": "...",
  "timestamp": 1720000001,
  "v": 1
}
```

**Client auth failure** (`error`):

```json
{
  "success": false,
  "error": "License tier must be higher than the current tier",
  "code": "TIER_NOT_HIGHER"
}
```

## API

### `Sdkey->new(...)` / `Sdkey::Client->new(...)`

| Option | Type | Description |
|---|---|---|
| `api_base_url` | string | API origin (no trailing slash) |
| `app_id` | string | Application UUID |
| `app_version` | string | Exact app version → sent as `clientVersion` |
| `app_public_key_b64` | string | Raw Ed25519 public key (32 bytes), base64 |
| `http_post` | coderef | Optional HTTP POST override: `sub ($url, $body_hash) { ($status, $json_hash) }` |

### Methods

- `init()` — challenge handshake; verifies the signed hello; derives the AES session key; sends `clientVersion`
- `validate($license_key, $hwid?)` — sealed validate; omits `hwid` JSON key when not provided; **always** decrypts then verifies the Ed25519 signature before trusting `success`
- `register(...)` / `login(...)` / `upgrade(...)` — plaintext `POST /api/v1/client/*`
- `get_session()` / `clear_session()` — inspect or drop the local session

### Errors

Protocol / transport failures throw `Sdkey::Error` with `code` and `message` (server `error` text when the API provides one):

`INIT_FAILED` · `APP_OUTDATED` · `HELLO_SIGNATURE_INVALID` · `VALIDATE_RESPONSE_INVALID` · `RESPONSE_SIGNATURE_INVALID` · `SESSION_MISMATCH` · `CLOCK_SKEW` · `NETWORK`

License denials (banned, HWID mismatch, etc.) return a normal validate result with `success => 0` — they are not thrown. Auth denials return `{ success => 0, code => ..., error => ... }`.

This package does **not** include developer tooling / Bearer (`sdk_live_…`) management APIs.

## Security notes

- Never ship app **private** keys in a client.
- Do not skip signature verification — that is the anti-spoof binding.
- This package is open source; the SDKey server remains a separate product.

## Development

```bash
cpanm --installdeps .
prove -lrv t
```

## License

MIT

## Repository

https://github.com/SDKeyDev/sdkey-perl
