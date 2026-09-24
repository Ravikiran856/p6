/// Three-color risk enum used by badges, charts, and the results gauge.
enum RiskLevel {
  safe,
  suspicious,
  highRisk,
  unknown;

  static RiskLevel fromApi(String? raw) {
    switch (raw) {
      case 'safe':
        return RiskLevel.safe;
      case 'suspicious':
        return RiskLevel.suspicious;
      case 'high_risk':
        return RiskLevel.highRisk;
      default:
        return RiskLevel.unknown;
    }
  }

  String get apiValue {
    switch (this) {
      case RiskLevel.safe:
        return 'safe';
      case RiskLevel.suspicious:
        return 'suspicious';
      case RiskLevel.highRisk:
        return 'high_risk';
      case RiskLevel.unknown:
        return 'unknown';
    }
  }

  String get label {
    switch (this) {
      case RiskLevel.safe:
        return 'Safe';
      case RiskLevel.suspicious:
        return 'Suspicious';
      case RiskLevel.highRisk:
        return 'High Risk';
      case RiskLevel.unknown:
        return 'Unknown';
    }
  }

  /// Midpoints matching the backend SCORE_CUTOFFS (for trend chart when only a label exists).
  double get estimatedScore {
    switch (this) {
      case RiskLevel.safe:
        return 15;
      case RiskLevel.suspicious:
        return 45;
      case RiskLevel.highRisk:
        return 82;
      case RiskLevel.unknown:
        return 0;
    }
  }
}
