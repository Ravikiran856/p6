import 'dart:math' as math;
import 'package:flutter/material.dart';

import '../../../../core/theme/app_colors.dart';

/// Speedometer-style animated risk gauge (0 - 100).
///
/// VIVA ARCHITECTURE NOTE:
/// Custom vector canvas painter with an [AnimationController] simulating a high-precision
/// cybersecurity gauge. The arc sweeps from 135° to 405° (270° total span), with colors
/// smoothly interpolating from electric green (#00FF9C) -> warning amber (#FFB020) -> alert red (#FF4757).
class RiskGauge extends StatefulWidget {
  const RiskGauge({
    super.key,
    required this.score,
    this.size = 220,
  });

  final double score;
  final double size;

  @override
  State<RiskGauge> createState() => _RiskGaugeState();
}

class _RiskGaugeState extends State<RiskGauge>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 1400),
  );
  late Animation<double> _animation;

  @override
  void initState() {
    super.initState();
    _animation = Tween<double>(begin: 0.0, end: widget.score.clamp(0.0, 100.0))
        .animate(CurvedAnimation(parent: _controller, curve: Curves.easeOutCubic));
    _controller.forward();
  }

  @override
  void didUpdateWidget(covariant RiskGauge oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.score != widget.score) {
      _animation = Tween<double>(begin: _animation.value, end: widget.score.clamp(0.0, 100.0))
          .animate(CurvedAnimation(parent: _controller, curve: Curves.easeOutCubic));
      _controller.forward(from: 0.0);
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Color _scoreColor(double score) {
    if (score < 30) return AppColors.safe;
    if (score < 70) return AppColors.suspicious;
    return AppColors.highRisk;
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _animation,
      builder: (context, _) {
        final current = _animation.value;
        final color = _scoreColor(current);

        return SizedBox(
          width: widget.size,
          height: widget.size * 0.88,
          child: Stack(
            alignment: Alignment.center,
            children: [
              CustomPaint(
                size: Size(widget.size, widget.size),
                painter: _GaugePainter(
                  progress: current / 100.0,
                  activeColor: color,
                ),
              ),
              Positioned(
                bottom: widget.size * 0.18,
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(
                      current.toStringAsFixed(1),
                      style: TextStyle(
                        fontSize: widget.size * 0.19,
                        fontWeight: FontWeight.w800,
                        color: color,
                        letterSpacing: -1,
                      ),
                    ),
                    Text(
                      'RISK SCORE (0-100)',
                      style: TextStyle(
                        fontSize: widget.size * 0.052,
                        letterSpacing: 1.2,
                        color: AppColors.textMuted,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}

class _GaugePainter extends CustomPainter {
  _GaugePainter({required this.progress, required this.activeColor});

  final double progress;
  final Color activeColor;

  static const double _startAngle = 135 * (math.pi / 180);
  static const double _totalAngle = 270 * (math.pi / 180);

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height * 0.52);
    final radius = size.width * 0.40;
    const strokeWidth = 14.0;

    // Background track arc
    final trackPaint = Paint()
      ..color = AppColors.surfaceElevated
      ..style = PaintingStyle.stroke
      ..strokeWidth = strokeWidth
      ..strokeCap = StrokeCap.round;

    canvas.drawArc(
      Rect.fromCircle(center: center, radius: radius),
      _startAngle,
      _totalAngle,
      false,
      trackPaint,
    );

    // Active illuminated gradient arc
    if (progress > 0) {
      final sweep = _totalAngle * progress.clamp(0.01, 1.0);

      final activePaint = Paint()
        ..shader = SweepGradient(
          startAngle: _startAngle,
          endAngle: _startAngle + _totalAngle,
          colors: const [
            AppColors.safe,
            AppColors.suspicious,
            AppColors.highRisk,
          ],
          stops: const [0.0, 0.5, 1.0],
          transform: GradientRotation(_startAngle),
        ).createShader(Rect.fromCircle(center: center, radius: radius))
        ..style = PaintingStyle.stroke
        ..strokeWidth = strokeWidth
        ..strokeCap = StrokeCap.round;

      canvas.drawArc(
        Rect.fromCircle(center: center, radius: radius),
        _startAngle,
        sweep,
        false,
        activePaint,
      );

      // Glowing needle head dot at current position
      final endAngle = _startAngle + sweep;
      final headX = center.dx + radius * math.cos(endAngle);
      final headY = center.dy + radius * math.sin(endAngle);

      final glowPaint = Paint()
        ..color = activeColor.withOpacity( 0.4)
        ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 8);
      canvas.drawCircle(Offset(headX, headY), 10, glowPaint);

      final dotPaint = Paint()..color = activeColor;
      canvas.drawCircle(Offset(headX, headY), 6, dotPaint);

      final innerWhite = Paint()..color = Colors.white;
      canvas.drawCircle(Offset(headX, headY), 2.5, innerWhite);
    }
  }

  @override
  bool shouldRepaint(covariant _GaugePainter oldDelegate) =>
      oldDelegate.progress != progress || oldDelegate.activeColor != activeColor;
}
