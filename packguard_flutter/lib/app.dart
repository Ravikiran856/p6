import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'core/notifications/notification_service.dart';
import 'core/routing/app_router.dart';
import 'core/theme/app_theme.dart';
import 'core/theme/theme_provider.dart';

class PackGuardApp extends ConsumerStatefulWidget {
  const PackGuardApp({super.key});

  @override
  ConsumerState<PackGuardApp> createState() => _PackGuardAppState();
}

class _PackGuardAppState extends ConsumerState<PackGuardApp> {
  @override
  void initState() {
    super.initState();
    // Initialize FCM notification listener for rescan alerts
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(notificationServiceProvider).initialize(context);
    });
  }

  @override
  Widget build(BuildContext context) {
    final router = ref.watch(routerProvider);
    final themeMode = ref.watch(themeModeProvider);

    return MaterialApp.router(
      title: 'PackGuard',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.light,
      darkTheme: AppTheme.dark,
      themeMode: themeMode,
      routerConfig: router,
    );
  }
}
