import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import '../../features/auth/presentation/login_screen.dart';
import '../../features/auth/presentation/signup_screen.dart';
import '../../features/dashboard/presentation/dashboard_screen.dart';
import '../../features/graph/presentation/dependency_graph_screen.dart';
import '../../features/history/presentation/scan_history_screen.dart';
import '../../features/onboarding/presentation/splash_screen.dart';
import '../../features/results/presentation/results_screen.dart';
import '../../features/scan/presentation/live_scan_progress_screen.dart';
import '../../features/scan/presentation/scan_input_screen.dart';
import '../../features/settings/presentation/settings_screen.dart';
import '../../features/shell/presentation/main_shell.dart';
import '../session/session_provider.dart';

final _rootKey = GlobalKey<NavigatorState>();

final routerProvider = Provider<GoRouter>((ref) {
  final listenable = _SessionListenable(ref);

  return GoRouter(
    navigatorKey: _rootKey,
    initialLocation: '/splash',
    refreshListenable: listenable,
    redirect: (context, state) {
      final loc = state.matchedLocation;
      final authed = ref.read(sessionProvider).isAuthenticated;
      final onSplash = loc == '/splash';
      final onAuth = loc == '/login' || loc == '/signup';

      if (onSplash) return null;
      if (!authed && !onAuth) return '/login';
      if (authed && onAuth) return '/dashboard';
      return null;
    },
    routes: [
      GoRoute(path: '/splash', builder: (_, __) => const SplashScreen()),
      GoRoute(path: '/login', builder: (_, __) => const LoginScreen()),
      GoRoute(path: '/signup', builder: (_, __) => const SignupScreen()),
      GoRoute(path: '/scan/progress', builder: (_, __) => const LiveScanProgressScreen()),
      GoRoute(path: '/scan/results', builder: (_, __) => const ResultsScreen()),
      GoRoute(
        path: '/scan/graph/:packageName',
        builder: (context, state) => DependencyGraphScreen(
          packageName: state.pathParameters['packageName'] ?? '',
        ),
      ),
      StatefulShellRoute.indexedStack(
        builder: (context, state, navigationShell) {
          return MainShell(navigationShell: navigationShell);
        },
        branches: [
          StatefulShellBranch(routes: [
            GoRoute(path: '/dashboard', builder: (_, __) => const DashboardScreen()),
          ]),
          StatefulShellBranch(routes: [
            GoRoute(path: '/scan', builder: (_, __) => const ScanInputScreen()),
          ]),
          StatefulShellBranch(routes: [
            GoRoute(path: '/history', builder: (_, __) => const ScanHistoryScreen()),
          ]),
          StatefulShellBranch(routes: [
            GoRoute(path: '/settings', builder: (_, __) => const SettingsScreen()),
          ]),
        ],
      ),
    ],
  );
});

/// go_router needs a Listenable; we tick it whenever session changes.
class _SessionListenable extends ChangeNotifier {
  _SessionListenable(this._ref) {
    _ref.listen(sessionProvider, (_, __) => notifyListeners());
  }
  final Ref _ref;
}
