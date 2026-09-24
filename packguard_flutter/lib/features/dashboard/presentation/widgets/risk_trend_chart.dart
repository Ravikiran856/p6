import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';

import '../../../../core/theme/app_colors.dart';
import '../../../../shared_models/risk_level.dart';
import '../../../scan/data/models/scan_models.dart';

/// Mini trend of the last N history items. We map risk *labels* to the same
/// midpoints the Random Forest uses (15 / 45 / 82) because `/scan/history`
/// does not return numeric scores.
class RiskTrendChart extends StatelessWidget {
  const RiskTrendChart({super.key, required this.items});

  final List<HistoryItem> items;

  @override
  Widget build(BuildContext context) {
    final points = items.reversed.toList();
    if (points.isEmpty) {
      return const SizedBox(
        height: 140,
        child: Center(
          child: Text('No scans yet — run one to see your risk trend.',
              style: TextStyle(color: AppColors.textMuted)),
        ),
      );
    }

    final spots = <FlSpot>[];
    for (var i = 0; i < points.length; i++) {
      final level = RiskLevel.fromApi(points[i].overallRiskLevel);
      spots.add(FlSpot(i.toDouble(), level.estimatedScore));
    }

    // Guard fl_chart coordinate math when only 1 scan exists (prevents minX == maxX assertion error)
    final double maxX = spots.length <= 1 ? 1.0 : (spots.length - 1).toDouble();

    return SizedBox(
      height: 160,
      child: LineChart(
        LineChartData(
          minX: 0,
          maxX: maxX,
          minY: 0,
          maxY: 100,
          lineTouchData: LineTouchData(
            handleBuiltInTouches: true,
            touchTooltipData: LineTouchTooltipData(
              getTooltipColor: (_) => AppColors.surfaceElevated,
              tooltipRoundedRadius: 8,
              getTooltipItems: (touchedSpots) {
                return touchedSpots.map((spot) {
                  final index = spot.x.toInt();
                  final item = (index >= 0 && index < points.length) ? points[index] : null;
                  final name = item?.displayName ?? 'Scan';
                  final level = item != null ? RiskLevel.fromApi(item.overallRiskLevel) : RiskLevel.unknown;
                  return LineTooltipItem(
                    '$name\n${level.label} (${spot.y.toInt()}/100)',
                    TextStyle(
                      color: level == RiskLevel.safe
                          ? AppColors.safe
                          : level == RiskLevel.suspicious
                              ? AppColors.suspicious
                              : AppColors.highRisk,
                      fontWeight: FontWeight.w600,
                      fontSize: 12,
                    ),
                  );
                }).toList();
              },
            ),
          ),
          gridData: FlGridData(
            show: true,
            drawVerticalLine: false,
            getDrawingHorizontalLine: (v) => const FlLine(
              color: AppColors.border,
              strokeWidth: 0.6,
            ),
          ),
          titlesData: FlTitlesData(
            topTitles: const AxisTitles(sideTitles: SideTitles(showTitles: false)),
            rightTitles: const AxisTitles(sideTitles: SideTitles(showTitles: false)),
            leftTitles: AxisTitles(
              sideTitles: SideTitles(
                showTitles: true,
                reservedSize: 28,
                interval: 50,
                getTitlesWidget: (v, _) => Text(
                  v.toInt().toString(),
                  style: const TextStyle(color: AppColors.textMuted, fontSize: 10),
                ),
              ),
            ),
            bottomTitles: const AxisTitles(sideTitles: SideTitles(showTitles: false)),
          ),
          borderData: FlBorderData(show: false),
          lineBarsData: [
            LineChartBarData(
              spots: spots,
              isCurved: spots.length > 1,
              color: AppColors.accent,
              barWidth: 2.4,
              dotData: const FlDotData(show: true),
              belowBarData: BarAreaData(
                show: true,
                color: AppColors.accent.withOpacity( 0.12),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
