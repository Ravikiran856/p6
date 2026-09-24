import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../core/constants/app_constants.dart';
import '../../../core/session/session_provider.dart';
import '../../../core/theme/app_colors.dart';
import '../../auth/application/auth_providers.dart';

/// First frame: pulsing shield + tagline, then route on auth state.
class SplashScreen extends ConsumerStatefulWidget {
  const SplashScreen({super.key});

  @override
  ConsumerState<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends ConsumerState<SplashScreen>
    with SingleTickerProviderStateMixin {
  late final AnimationController _pulse = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 1400),
  )..repeat(reverse: true);

  @override
  void initState() {
    super.initState();
    // Allow animation to run at least 1.6s so the brand and tagline register
    Future<void>.delayed(const Duration(milliseconds: 1600), _evaluateAuthAndNavigate);
  }

  /// Restores session credentials and routes accordingly.
  /// Wrapped in try-catch so network hiccups during splash won't crash the application.
  Future<void> _evaluateAuthAndNavigate() async {
    try {
      await ref.read(authControllerProvider.notifier).restore();
    } catch (_) {
      // Ignored: network failure during splash falls back to login screen
    }
    if (!mounted) return;
    final authed = ref.read(sessionProvider).isAuthenticated;
    context.go(authed ? '/dashboard' : '/login');
  }

  @override
  void dispose() {
    _pulse.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: AnimatedBuilder(
          animation: _pulse,
          builder: (context, child) {
            final t = _pulse.value;
            return Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Transform.scale(
                  scale: 0.94 + (t * 0.08),
                  child: Container(
                    width: 112,
                    height: 112,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: AppColors.surface,
                      boxShadow: [
                        BoxShadow(
                          color: AppColors.accent.withOpacity( 0.18 + t * 0.22),
                          blurRadius: 28 + t * 18,
                        ),
                      ],
                      border: Border.all(
                        color: AppColors.accent.withOpacity( 0.55 + t * 0.35),
                        width: 1.4,
                      ),
                    ),
                    child: CustomPaint(
                      painter: _ShieldPainter(progress: t),
                    ),
                  ),
                ),
                const SizedBox(height: 28),
                Text(
                  AppConstants.appName,
                  style: Theme.of(context).textTheme.displayLarge,
                ),
                const SizedBox(height: 8),
                Text(
                  AppConstants.tagline,
                  style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                        color: AppColors.accent,
                        letterSpacing: 0.6,
                      ),
                ),
              ],
            );
          },
        ),
      ),
    );
  }
}

/// Simple custom shield — no Lottie asset required for the viva demo.
class _ShieldPainter extends CustomPainter {
  _ShieldPainter({required this.progress});
  final double progress;

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = AppColors.accent
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2.4
      ..strokeJoin = StrokeJoin.round;

    final path = Path();
    final w = size.width;
    final h = size.height;
    path.moveTo(w * 0.5, h * 0.18);
    path.lineTo(w * 0.78, h * 0.30);
    path.lineTo(w * 0.78, h * 0.52);
    path.quadraticBezierTo(w * 0.78, h * 0.78, w * 0.5, h * 0.86);
    path.quadraticBezierTo(w * 0.22, h * 0.78, w * 0.22, h * 0.52);
    path.lineTo(w * 0.22, h * 0.30);
    path.close();
    canvas.drawPath(path, paint);

    final scanY = h * (0.32 + 0.4 * progress);
    canvas.drawLine(
      Offset(w * 0.30, scanY),
      Offset(w * 0.70, scanY),
      paint..strokeWidth = 1.6,
    );

    // Check mark that fades in with the pulse.
    final check = Paint()
      ..color = AppColors.accent.withOpacity( 0.35 + progress * 0.65)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2.6
      ..strokeCap = StrokeCap.round;
    canvas.drawLine(Offset(w * 0.40, h * 0.52), Offset(w * 0.47, h * 0.60), check);
    canvas.drawLine(Offset(w * 0.47, h * 0.60), Offset(w * 0.62, h * 0.42), check);
  }

  @override
  bool shouldRepaint(covariant _ShieldPainter oldDelegate) =>
      oldDelegate.progress != progress;
}
