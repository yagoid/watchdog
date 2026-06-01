//! Detection stage: runs a fixed set of heuristic detectors over each
//! `EnrichedEvent` and combines their sub-scores probabilistically into
//! a single `ScoredEvent`.
//!
//! `score = 1 - Π (1 - sub_score_i)` — every detector contributes
//! independently. A perfectly benign event gets `0.0`. Two mid-confidence
//! signals (each `0.5`) yield `0.75`, not `1.0`, so detectors don't
//! drown each other out.

mod baseline;
mod detector;
mod detectors;
mod paths;
mod scorer;
mod signature;

pub use baseline::{Baseline, ImageProfile};
pub use detector::Detector;
pub use scorer::Scorer;
pub use signature::{SignatureCache, SignatureStatus};
