/// REST paths under `/api/v1`. Keep in one place so screens never hardcode URLs.
class ApiEndpoints {
  ApiEndpoints._();

  /// Android emulator → host machine. Physical device: use your LAN IP.
  static const String baseUrl = String.fromEnvironment(
    'API_BASE_URL',
    defaultValue: 'http://10.0.2.2:8000/api/v1',
  );

  static const String health = '/health';
  static const String signup = '/auth/signup';
  static const String login = '/auth/login';
  static const String packageSearch = '/packages/search';
  static const String scanPackage = '/scan/package';
  static const String scanHistory = '/scan/history';
  static const String rescanCheck = '/scan/rescan-check';

  static String dependencyGraph(String packageName) =>
      '/scan/dependency-graph/$packageName';

  static String scanReportPdf(String scanId) => '/scan/report/$scanId/pdf';
}
