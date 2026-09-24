/// Brand + risk-level tokens. Dark-mode only — PackGuard never ships a light theme in v1.
///
/// Mapping used in the viva:
///   background  #0D1117  GitHub-style void
///   safe        #00FF9C  electric green
///   suspicious  #FFB020  amber
///   high_risk   #FF4757  alert red
library;

import 'package:flutter/material.dart';

class AppColors {
  AppColors._();

  static const Color background = Color(0xFF0D1117);
  static const Color surface = Color(0xFF161B22);
  static const Color surfaceElevated = Color(0xFF1F2630);
  static const Color border = Color(0xFF30363D);

  static const Color textPrimary = Color(0xFFE6EDF3);
  static const Color textSecondary = Color(0xFF8B949E);
  static const Color textMuted = Color(0xFF6E7681);

  static const Color accent = Color(0xFF00FF9C);
  static const Color safe = Color(0xFF00FF9C);
  static const Color suspicious = Color(0xFFFFB020);
  static const Color highRisk = Color(0xFFFF4757);

  static const Color inputFill = Color(0xFF0D1117);
  static const Color focusRing = Color(0xFF00FF9C);
}
