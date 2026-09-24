import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../features/scan/application/scan_providers.dart';
import '../../features/scan/data/models/scan_models.dart';
import '../theme/app_colors.dart';

/// Push Notification Service for PackGuard
///
/// VIVA ARCHITECTURE EXPLANATION:
/// 1. Asynchronous Rescan Alerts: The FastAPI backend runs `/scan/rescan-check` in background
///    tasks or via cron. When a monitored package releases a new version or changes risk
///    profile, it dispatches an FCM payload to the user device.
/// 2. Foreground & Background Listeners: Handles incoming message streams without blocking UI.
/// 3. Deep-Linking: Directly resolves package metadata and pushes the user to [ResultsScreen].
class NotificationService {
  NotificationService(this._ref);

  final Ref _ref;
  bool _initialized = false;

  Future<void> initialize(BuildContext context) async {
    if (_initialized) return;
    _initialized = true;

    try {
      final fcm = FirebaseMessaging.instance;

      // Request notification permissions (iOS/Android 13+)
      final settings = await fcm.requestPermission(
        alert: true,
        badge: true,
        sound: true,
      );

      if (settings.authorizationStatus == AuthorizationStatus.authorized) {
        debugPrint('FCM Notifications authorized');
      }

      // Foreground message listener
      FirebaseMessaging.onMessage.listen((RemoteMessage message) {
        _handleForegroundMessage(context, message);
      });

      // Background message click listener
      FirebaseMessaging.onMessageOpenedApp.listen((RemoteMessage message) {
        _handleNotificationDeepLink(context, message.data);
      });

      // Check initial message if app opened directly from cold push
      final initialMessage = await fcm.getInitialMessage();
      if (initialMessage != null) {
        _handleNotificationDeepLink(context, initialMessage.data);
      }
    } catch (e) {
      // In demo mode without google-services.json, FirebaseMessaging fails gracefully
      debugPrint('FCM NotificationService initialization bypassed (Demo mode): $e');
    }
  }

  void _handleForegroundMessage(BuildContext context, RemoteMessage message) {
    HapticFeedback.heavyImpact();

    final data = message.data;
    final pkgName = data['packageName'] ?? message.notification?.title ?? 'Watched Package';
    final newRisk = data['riskLevel'] ?? 'high_risk';

    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        backgroundColor: AppColors.surface,
        duration: const Duration(seconds: 6),
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: const BorderSide(color: AppColors.highRisk, width: 1.5),
        ),
        content: Row(
          children: [
            const Icon(Icons.warning_amber_rounded, color: AppColors.highRisk, size: 24),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Risk Alert: $pkgName',
                    style: const TextStyle(
                      color: AppColors.textPrimary,
                      fontWeight: FontWeight.w700,
                      fontSize: 14,
                    ),
                  ),
                  Text(
                    'Re-scan flagged package as $newRisk.',
                    style: const TextStyle(color: AppColors.textMuted, fontSize: 12),
                  ),
                ],
              ),
            ),
          ],
        ),
        action: SnackBarAction(
          label: 'View Results',
          textColor: AppColors.accent,
          onPressed: () => _handleNotificationDeepLink(context, data),
        ),
      ),
    );
  }

  void _handleNotificationDeepLink(BuildContext context, Map<String, dynamic> data) {
    final pkgName = data['packageName'] as String? ?? 'requests';
    final riskLevel = data['riskLevel'] as String? ?? 'high_risk';
    final riskScore = double.tryParse(data['riskScore']?.toString() ?? '85.0') ?? 85.0;

    // Populate lastScanResultProvider
    _ref.read(lastScanResultProvider.notifier).state = ScanResult(
      packageName: pkgName,
      packageVersion: data['version'] as String? ?? 'latest',
      riskScore: riskScore,
      riskLabel: riskLevel,
      explanation: [
        'Automated background re-scan triggered by PackGuard Watcher.',
        'Package dependency risk score elevated to $riskScore/100.',
      ],
      dependencyTree: [],
      timestamp: DateTime.now().toIso8601String(),
      scanId: data['scanId'] as String?,
    );

    // Deep-link to results screen
    context.push('/scan/results');
  }

  /// Viva Demo Helper: Simulates an incoming FCM notification for evaluation
  void triggerMockRescanAlert(BuildContext context, {String pkgName = 'requests-oauthlib'}) {
    _handleForegroundMessage(
      context,
      RemoteMessage(
        notification: const RemoteNotification(
          title: 'PackGuard Watcher',
          body: 'Security status altered for monitored package',
        ),
        data: {
          'packageName': pkgName,
          'riskLevel': 'high_risk',
          'riskScore': '88.5',
          'version': '2.1.0',
        },
      ),
    );
  }
}

final notificationServiceProvider = Provider<NotificationService>((ref) {
  return NotificationService(ref);
});
