class AppConstants {
  AppConstants._();

  static const String appName = 'PackGuard';
  static const String tagline = 'Scan Smart. Ship Safe.';

  /// Live-progress UX: even a fast backend must hold each step this long
  /// so the user can read the pipeline (IEEE/viva talking point: UX vs latency).
  static const Duration minStepDuration = Duration(milliseconds: 1500);

  static const Duration searchDebounce = Duration(milliseconds: 350);

  static const int historyPageSize = 20;
}
