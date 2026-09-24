import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../../../core/session/session_provider.dart';
import '../../../core/theme/app_colors.dart';
import '../../../core/theme/theme_provider.dart';
import '../../auth/application/auth_providers.dart';

/// Full Settings & Security Analyst Profile Screen
///
/// VIVA ARCHITECTURE EXPLANATION:
/// 1. Identity & Session: Reflects authenticated analyst state stored in [sessionProvider].
/// 2. Notification Preferences: Toggles push alerts for asynchronous package re-scanning.
/// 3. Dynamic Theming: Switcher between the standard dark cybersecurity theme (#0D1117)
///    and high-contrast light mode, demonstrating theme management completeness.
/// 4. Safe Sign-out: Clears local session tokens, caches, and transitions to auth route.
class SettingsScreen extends ConsumerStatefulWidget {
  const SettingsScreen({super.key});

  @override
  ConsumerState<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends ConsumerState<SettingsScreen> {
  bool _pushEnabled = true;

  @override
  void initState() {
    super.initState();
    _loadNotificationPref();
  }

  Future<void> _loadNotificationPref() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      setState(() {
        _pushEnabled = prefs.getBool('fcm_push_enabled') ?? true;
      });
    } catch (_) {}
  }

  Future<void> _togglePush(bool val) async {
    HapticFeedback.selectionClick();
    setState(() => _pushEnabled = val);
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setBool('fcm_push_enabled', val);
    } catch (_) {}

    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(val ? 'Push alerts enabled' : 'Push alerts muted'),
          duration: const Duration(seconds: 2),
        ),
      );
    }
  }

  void _confirmSignOut() {
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.surface,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: const Text('Sign out of PackGuard?'),
        content: const Text(
          'Your active session tokens will be revoked and offline cache cleared.',
          style: TextStyle(color: AppColors.textSecondary),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel', style: TextStyle(color: AppColors.textMuted)),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(ctx);
              ref.read(authControllerProvider.notifier).signOut();
              context.go('/login');
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.highRisk,
              foregroundColor: Colors.white,
            ),
            child: const Text('Sign out'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final session = ref.watch(sessionProvider);
    final themeMode = ref.watch(themeModeProvider);
    final isDark = themeMode == ThemeMode.dark;

    final displayName = session.displayName ?? session.email?.split('@').first ?? 'Security Analyst';
    final email = session.email ?? 'analyst@packguard.dev';
    final uid = session.uid ?? 'local-device-uid';

    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings & Profile'),
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
          children: [
            // Analyst Identity Card
            Container(
              padding: const EdgeInsets.all(18),
              decoration: BoxDecoration(
                color: AppColors.surface,
                borderRadius: BorderRadius.circular(16),
                border: Border.all(color: AppColors.border),
              ),
              child: Row(
                children: [
                  Container(
                    width: 52,
                    height: 52,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: AppColors.surfaceElevated,
                      border: Border.all(color: AppColors.accent, width: 1.5),
                    ),
                    child: const Icon(Icons.security, color: AppColors.accent, size: 28),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          displayName,
                          style: const TextStyle(
                            fontSize: 17,
                            fontWeight: FontWeight.w700,
                            color: AppColors.textPrimary,
                          ),
                        ),
                        const SizedBox(height: 2),
                        Text(
                          email,
                          style: const TextStyle(color: AppColors.textSecondary, fontSize: 13),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          'UID: ${uid.substring(0, uid.length >= 12 ? 12 : uid.length)}…',
                          style: const TextStyle(color: AppColors.textMuted, fontSize: 11),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),

            const SizedBox(height: 28),

            // Section Header: App Preferences
            const Text(
              'APPLICATION PREFERENCES',
              style: TextStyle(
                color: AppColors.textMuted,
                fontSize: 11,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.1,
              ),
            ),
            const SizedBox(height: 10),

            // Push Notifications Toggle
            Container(
              decoration: BoxDecoration(
                color: AppColors.surface,
                borderRadius: BorderRadius.circular(14),
                border: Border.all(color: AppColors.border),
              ),
              child: SwitchListTile(
                contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                secondary: Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: AppColors.surfaceElevated,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: const Icon(Icons.notifications_active_outlined, color: AppColors.accent, size: 20),
                ),
                title: const Text(
                  'FCM Push Alerts',
                  style: TextStyle(fontWeight: FontWeight.w600, fontSize: 15),
                ),
                subtitle: const Text(
                  'Notify when watched packages are re-flagged by rescan-check',
                  style: TextStyle(color: AppColors.textMuted, fontSize: 12),
                ),
                activeColor: AppColors.accent,
                value: _pushEnabled,
                onChanged: _togglePush,
              ),
            ),

            const SizedBox(height: 10),

            // Dark / Light Mode Toggle
            Container(
              decoration: BoxDecoration(
                color: AppColors.surface,
                borderRadius: BorderRadius.circular(14),
                border: Border.all(color: AppColors.border),
              ),
              child: SwitchListTile(
                contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                secondary: Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: AppColors.surfaceElevated,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Icon(
                    isDark ? Icons.dark_mode_outlined : Icons.light_mode_outlined,
                    color: AppColors.accent,
                    size: 20,
                  ),
                ),
                title: const Text(
                  'Dark Theme (#0D1117)',
                  style: TextStyle(fontWeight: FontWeight.w600, fontSize: 15),
                ),
                subtitle: Text(
                  isDark ? 'Cybersecurity void dark mode enabled' : 'High-contrast light mode enabled',
                  style: const TextStyle(color: AppColors.textMuted, fontSize: 12),
                ),
                activeColor: AppColors.accent,
                value: isDark,
                onChanged: (_) {
                  HapticFeedback.selectionClick();
                  ref.read(themeModeProvider.notifier).toggle();
                },
              ),
            ),

            const SizedBox(height: 28),

            // Section Header: About PackGuard
            const Text(
              'ABOUT PACKGUARD',
              style: TextStyle(
                color: AppColors.textMuted,
                fontSize: 11,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.1,
              ),
            ),
            const SizedBox(height: 10),

            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: AppColors.surface,
                borderRadius: BorderRadius.circular(14),
                border: Border.all(color: AppColors.border),
              ),
              child: const Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(Icons.shield_outlined, color: AppColors.accent, size: 20),
                      SizedBox(width: 8),
                      Text(
                        'PackGuard Core v0.1.0',
                        style: TextStyle(fontWeight: FontWeight.w700, fontSize: 15),
                      ),
                      Spacer(),
                      Text(
                        'IEEE / Final Year Viva',
                        style: TextStyle(color: AppColors.textMuted, fontSize: 11),
                      ),
                    ],
                  ),
                  SizedBox(height: 10),
                  Text(
                    'AI-driven malicious-package detection with risk visualization for open-source Python packages.',
                    style: TextStyle(color: AppColors.textSecondary, fontSize: 13, height: 1.4),
                  ),
                  SizedBox(height: 12),
                  Divider(color: AppColors.border, height: 1),
                  SizedBox(height: 10),
                  Text(
                    'Pipeline: PyPI JSON API → AST Static Extraction → Levenshtein Typosquatting → Random Forest Classifier (100 Trees).',
                    style: TextStyle(color: AppColors.textMuted, fontSize: 11, height: 1.3),
                  ),
                ],
              ),
            ),

            const SizedBox(height: 36),

            // Logout CTA
            OutlinedButton.icon(
              onPressed: _confirmSignOut,
              icon: const Icon(Icons.logout, size: 18, color: AppColors.highRisk),
              label: const Text('Sign out of PackGuard'),
              style: OutlinedButton.styleFrom(
                minimumSize: const Size.fromHeight(50),
                side: BorderSide(color: AppColors.highRisk.withOpacity( 0.6)),
                foregroundColor: AppColors.highRisk,
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
