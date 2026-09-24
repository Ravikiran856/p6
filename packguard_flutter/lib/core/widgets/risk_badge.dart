import 'package:flutter/material.dart';

import '../theme/app_colors.dart';
import '../../shared_models/risk_level.dart';

/// Compact pill used on dashboard cards and scan results.
class RiskBadge extends StatelessWidget {
  const RiskBadge({super.key, required this.level, this.compact = false});

  final RiskLevel level;
  final bool compact;

  Color get _color {
    switch (level) {
      case RiskLevel.safe:
        return AppColors.safe;
      case RiskLevel.suspicious:
        return AppColors.suspicious;
      case RiskLevel.highRisk:
        return AppColors.highRisk;
      case RiskLevel.unknown:
        return AppColors.textMuted;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: EdgeInsets.symmetric(
        horizontal: compact ? 8 : 10,
        vertical: compact ? 3 : 5,
      ),
      decoration: BoxDecoration(
        color: _color.withOpacity( 0.12),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: _color.withOpacity( 0.55)),
      ),
      child: Text(
        level.label,
        style: TextStyle(
          color: _color,
          fontSize: compact ? 11 : 12,
          fontWeight: FontWeight.w600,
        ),
      ),
    );
  }
}
