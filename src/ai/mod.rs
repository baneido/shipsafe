pub mod fix;
pub mod triage;

// AI module - integrates with Claude API for:
// 1. Noise reduction / triage (prioritize truly exploitable findings)
// 2. Fix suggestion generation (generate code fixes for findings)
// 3. AI-generated code detection (identify and flag AI-written code patterns)
