import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../../../../core/theme/app_colors.dart';
import '../../../../core/widgets/risk_badge.dart';
import '../../../../shared_models/risk_level.dart';
import '../../../scan/data/models/scan_models.dart';

class RecentScanCard extends StatelessWidget {
  const RecentScanCard({super.key, required this.item, this.onTap});

  final HistoryItem item;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    DateTime? when;
    try {
      when = DateTime.tryParse(item.createdAt);
    } catch (_) {}
    final stamp = when == null ? item.createdAt : DateFormat.MMMd().add_Hm().format(when.toLocal());

    final isFile = item.type == 'requirements_file';
    final riskLevel = RiskLevel.fromApi(item.overallRiskLevel);

    return GestureDetector(
      onTap: onTap,
      child: Container(
        width: 180,
        margin: const EdgeInsets.only(right: 12),
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: AppColors.surface,
          borderRadius: BorderRadius.circular(16),
          border: Border.all(color: AppColors.border),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  isFile ? Icons.description_outlined : Icons.inventory_2_outlined,
                  size: 16,
                  color: AppColors.textMuted,
                ),
                const SizedBox(width: 6),
                Expanded(
                  child: Hero(
                    tag: 'pkg-${item.scanId}',
                    child: Material(
                      color: Colors.transparent,
                      child: Text(
                        item.displayName,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                          color: AppColors.textPrimary,
                          fontWeight: FontWeight.w600,
                          fontSize: 15,
                        ),
                      ),
                    ),
                  ),
                ),
              ],
            ),
            const Spacer(),
            RiskBadge(level: riskLevel, compact: true),
            const SizedBox(height: 8),
            Text(stamp, style: const TextStyle(color: AppColors.textMuted, fontSize: 11)),
          ],
        ),
      ),
    );
  }
}
