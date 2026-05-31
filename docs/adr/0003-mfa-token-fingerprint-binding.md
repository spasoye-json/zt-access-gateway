# MFA token bound to userId | deviceId | ip — not geo or user-agent

The MFA token embeds a hash of `userId | deviceId | ip` and is rejected if the presenting request doesn't match. The original requirement wording bound it to user-agent + geolocation; we changed it because user-agent churns on every browser update (false rejections) and geolocation adds privacy friction without matching the threat model, while an *unbound* token is replayable from any device within its TTL.

## Considered options

- **user-agent + geolocation (rejected):** brittle (UA churn) and privacy-invasive for weak binding.
- **userId only / IP only (rejected):** too loose — replayable across devices or across a shared NAT IP.
- **Add JA4H to the binding (deferred):** stronger, but deviceId + ip already closes the replay gap without the extra moving part.

Related: [ADR-0006](0006-separate-mfa-jwt-secret.md) (separate signing secret).
