#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcessRiskSignal {
    TemporaryDirectory,
    CacheDirectory,
    DownloadsDirectory,
    UnsignedExecutable,
    InvalidSignature,
    UnusualPermissions,
}

impl ProcessRiskSignal {
    pub const fn score(self) -> u8 {
        match self {
            Self::TemporaryDirectory => 30,
            Self::CacheDirectory => 15,
            Self::DownloadsDirectory => 20,
            Self::UnsignedExecutable => 35,
            Self::InvalidSignature => 50,
            Self::UnusualPermissions => 15,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessRiskLevel {
    Safe,
    Observe,
    ReviewRecommended,
    HighAnomaly,
}

impl ProcessRiskLevel {
    pub const fn from_score(score: u8) -> Self {
        match score {
            0..=29 => Self::Safe,
            30..=59 => Self::Observe,
            60..=79 => Self::ReviewRecommended,
            _ => Self::HighAnomaly,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRiskAssessment {
    pub pid: u32,
    pub name: String,
    pub score: u8,
    pub level: ProcessRiskLevel,
    pub signals: Vec<ProcessRiskSignal>,
}

impl ProcessRiskAssessment {
    pub fn new(pid: u32, name: impl Into<String>, signals: Vec<ProcessRiskSignal>) -> Self {
        let mut unique = Vec::with_capacity(signals.len());

        for signal in signals {
            if !unique.contains(&signal) {
                unique.push(signal);
            }
        }

        let score = unique
            .iter()
            .map(|signal| u16::from(signal.score()))
            .sum::<u16>()
            .min(100) as u8;

        Self {
            pid,
            name: name.into(),
            score,
            level: ProcessRiskLevel::from_score(score),
            signals: unique,
        }
    }

    pub const fn requires_attention(&self) -> bool {
        matches!(
            self.level,
            ProcessRiskLevel::ReviewRecommended | ProcessRiskLevel::HighAnomaly
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_score_is_classified_correctly() {
        let assessment = ProcessRiskAssessment::new(1, "safe", vec![]);
        assert_eq!(assessment.score, 0);
        assert_eq!(assessment.level, ProcessRiskLevel::Safe);
    }

    #[test]
    fn observe_score_is_classified_correctly() {
        let assessment =
            ProcessRiskAssessment::new(1, "observe", vec![ProcessRiskSignal::TemporaryDirectory]);
        assert_eq!(assessment.score, 30);
        assert_eq!(assessment.level, ProcessRiskLevel::Observe);
    }

    #[test]
    fn review_score_is_classified_correctly() {
        let assessment = ProcessRiskAssessment::new(
            1,
            "review",
            vec![
                ProcessRiskSignal::TemporaryDirectory,
                ProcessRiskSignal::CacheDirectory,
                ProcessRiskSignal::DownloadsDirectory,
            ],
        );
        assert_eq!(assessment.score, 65);
        assert_eq!(assessment.level, ProcessRiskLevel::ReviewRecommended);
    }

    #[test]
    fn score_is_limited_to_one_hundred() {
        let assessment = ProcessRiskAssessment::new(
            1,
            "high",
            vec![
                ProcessRiskSignal::TemporaryDirectory,
                ProcessRiskSignal::InvalidSignature,
                ProcessRiskSignal::UnsignedExecutable,
                ProcessRiskSignal::DownloadsDirectory,
            ],
        );
        assert_eq!(assessment.score, 100);
        assert_eq!(assessment.level, ProcessRiskLevel::HighAnomaly);
    }

    #[test]
    fn duplicate_signals_are_not_counted_twice() {
        let assessment = ProcessRiskAssessment::new(
            1,
            "dedupe",
            vec![
                ProcessRiskSignal::TemporaryDirectory,
                ProcessRiskSignal::TemporaryDirectory,
            ],
        );
        assert_eq!(assessment.score, 30);
        assert_eq!(assessment.signals.len(), 1);
    }
}
