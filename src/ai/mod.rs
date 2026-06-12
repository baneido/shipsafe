pub mod fix;
pub mod triage;

// AI layer (Claude API, BYOK via ANTHROPIC_API_KEY):
// - triage: noise reduction — classify findings as true/false positives and
//   exclude AI-confirmed false positives from the --fail-on gate (shipped).
// - fix: AI fix suggestion generation (planned).
