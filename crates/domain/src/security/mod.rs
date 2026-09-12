mod process_risk;

pub use process_risk::{
    ProcessRiskAssessment,
    ProcessRiskLevel,
    ProcessRiskSignal,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEventSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityEvent {
    pub id: i64,
    pub occurred_at: String,
    pub severity: SecurityEventSeverity,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallStatus {
    Enabled,
    Disabled,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileIntegrityStatus {
    BaselineCreated,
    Intact,
    Changed,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessSecurityStatus {
    Safe,
    ReviewRecommended,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatStatus {
    BasicProtectionActive,
    ProtectionReduced,
    ReviewRecommended,
    IntegrityWarning,
}

#[derive(Debug, Clone, Copy)]
pub struct SecuritySnapshot {
    pub open_port_count: usize,
    pub firewall_status: FirewallStatus,
    pub file_integrity_status: FileIntegrityStatus,
    pub warning_count: usize,
    pub threat_status: ThreatStatus,
}

impl Default for SecuritySnapshot {
    fn default() -> Self {
        Self {
            open_port_count: 0,
            firewall_status: FirewallStatus::Unknown,
            file_integrity_status: FileIntegrityStatus::Unknown,
            warning_count: 0,
            threat_status: ThreatStatus::ProtectionReduced,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CombinedSecuritySnapshot {
    pub open_port_count: usize,
    pub firewall_status: FirewallStatus,
    pub file_integrity_status: FileIntegrityStatus,
    pub analyzed_process_count: usize,
    pub suspicious_process_count: usize,
    pub process_status: ProcessSecurityStatus,
    pub warning_count: usize,
    pub threat_status: ThreatStatus,
}

impl SecuritySnapshot {
    pub fn combine_with_process_analysis(
        self,
        analyzed_process_count: usize,
        suspicious_process_count: usize,
    ) -> CombinedSecuritySnapshot {
        let process_status = if analyzed_process_count == 0 {
            ProcessSecurityStatus::Unknown
        } else if suspicious_process_count == 0 {
            ProcessSecurityStatus::Safe
        } else {
            ProcessSecurityStatus::ReviewRecommended
        };

        let warning_count = self.warning_count
            + usize::from(suspicious_process_count > 0);

        let threat_status = if suspicious_process_count > 0
            && self.threat_status == ThreatStatus::BasicProtectionActive
        {
            ThreatStatus::ReviewRecommended
        } else {
            self.threat_status
        };

        CombinedSecuritySnapshot {
            open_port_count: self.open_port_count,
            firewall_status: self.firewall_status,
            file_integrity_status: self.file_integrity_status,
            analyzed_process_count,
            suspicious_process_count,
            process_status,
            warning_count,
            threat_status,
        }
    }
}
