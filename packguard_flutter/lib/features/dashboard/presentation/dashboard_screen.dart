import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../../../core/session/session_provider.dart';
import '../../../core/theme/app_colors.dart';
import '../../../core/widgets/skeleton_loader.dart';
import '../../scan/application/scan_providers.dart';
import '../../scan/data/models/scan_models.dart';
import '../../scan/presentation/widgets/package_autocomplete_field.dart';
import '../application/dashboard_providers.dart';
import 'widgets/recent_scan_card.dart';
import 'widgets/risk_trend_chart.dart';

class DashboardScreen extends ConsumerWidget {
  const DashboardScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final session = ref.watch(sessionProvider);
    final history = ref.watch(dashboardHistoryProvider);
    final rescanAlerts = ref.watch(dashboardRescanAlertsProvider);
    final name = session.displayName ?? session.email?.split('@').first ?? 'analyst';
    final hour = DateTime.now().hour;
    final hello = hour < 12
        ? 'Good morning'
        : hour < 17
            ? 'Good afternoon'
            : 'Good evening';

    return SafeArea(
      child: RefreshIndicator(
        color: AppColors.accent,
        onRefresh: () async {
          ref.invalidate(dashboardHistoryProvider);
          ref.invalidate(dashboardRescanAlertsProvider);
        },
        child: ListView(
          padding: const EdgeInsets.fromLTRB(20, 16, 20, 24),
          children: [
            Text('$hello, $name', style: Theme.of(context).textTheme.headlineMedium),
            const SizedBox(height: 4),
            Text(
              DateFormat.yMMMMEEEEd().format(DateTime.now()),
              style: const TextStyle(color: AppColors.textMuted),
            ),
            const SizedBox(height: 20),
            PackageAutocompleteField(
              onSubmitted: (pkg) {
                ref.read(scanInputProvider.notifier).pickSuggestion(pkg);
                context.go('/scan');
              },
            ),
            const SizedBox(height: 20),

            // New CVE found in scanned packages summary card
            rescanAlerts.maybeWhen(
              data: (alerts) {
                if (alerts.isEmpty) return const SizedBox.shrink();
                final totalCves = alerts.fold<int>(0, (sum, a) => sum + a.knownVulnerabilities.length);
                return Padding(
                  padding: const EdgeInsets.only(bottom: 24),
                  child: Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: AppColors.surface,
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(color: AppColors.highRisk.withOpacity(0.5), width: 1.4),
                      boxShadow: [
                        BoxShadow(
                          color: AppColors.highRisk.withOpacity(0.12),
                          blurRadius: 16,
                          offset: const Offset(0, 4),
                        ),
                      ],
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Container(
                              padding: const EdgeInsets.all(8),
                              decoration: BoxDecoration(
                                color: AppColors.highRisk.withOpacity(0.15),
                                borderRadius: BorderRadius.circular(10),
                              ),
                              child: const Icon(Icons.shield_outlined, color: AppColors.highRisk, size: 22),
                            ),
                            const SizedBox(width: 12),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  const Text(
                                    'New CVE found in your scanned packages',
                                    style: TextStyle(
                                      color: AppColors.textPrimary,
                                      fontWeight: FontWeight.w700,
                                      fontSize: 14,
                                    ),
                                  ),
                                  const SizedBox(height: 2),
                                  Text(
                                    '$totalCves new ${totalCves == 1 ? "vulnerability" : "vulnerabilities"} across ${alerts.length} ${alerts.length == 1 ? "package" : "packages"} via OSV.dev',
                                    style: const TextStyle(
                                      color: AppColors.textMuted,
                                      fontSize: 11,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 12),
                        ...alerts.map((alert) {
                          return Container(
                            margin: const EdgeInsets.only(top: 8),
                            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                            decoration: BoxDecoration(
                              color: AppColors.background,
                              borderRadius: BorderRadius.circular(10),
                              border: Border.all(color: AppColors.border),
                            ),
                            child: Row(
                              children: [
                                Expanded(
                                  child: Column(
                                    crossAxisAlignment: CrossAxisAlignment.start,
                                    children: [
                                      Row(
                                        children: [
                                          Text(
                                            alert.packageName,
                                            style: const TextStyle(
                                              color: AppColors.textPrimary,
                                              fontWeight: FontWeight.w700,
                                              fontSize: 13,
                                            ),
                                          ),
                                          const SizedBox(width: 6),
                                          Text(
                                            'v${alert.newVersion}',
                                            style: const TextStyle(
                                              color: AppColors.textMuted,
                                              fontSize: 11,
                                            ),
                                          ),
                                        ],
                                      ),
                                      const SizedBox(height: 6),
                                      Wrap(
                                        spacing: 6,
                                        runSpacing: 4,
                                        children: alert.knownVulnerabilities.take(3).map((cve) {
                                          return Container(
                                            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                            decoration: BoxDecoration(
                                              color: AppColors.highRisk.withOpacity(0.12),
                                              borderRadius: BorderRadius.circular(4),
                                              border: Border.all(color: AppColors.highRisk.withOpacity(0.3)),
                                            ),
                                            child: Text(
                                              '${cve.cveId} · ${cve.severity}',
                                              style: const TextStyle(
                                                color: AppColors.highRisk,
                                                fontSize: 10,
                                                fontWeight: FontWeight.w600,
                                              ),
                                            ),
                                          );
                                        }).toList(),
                                      ),
                                    ],
                                  ),
                                ),
                                IconButton(
                                  icon: const Icon(Icons.radar, size: 20, color: AppColors.accent),
                                  tooltip: 'Re-audit package',
                                  onPressed: () {
                                    ref.read(scanInputProvider.notifier).pickSuggestion(alert.packageName);
                                    context.push('/scan/progress');
                                  },
                                ),
                              ],
                            ),
                          );
                        }),
                      ],
                    ),
                  ),
                );
              },
              orElse: () => const SizedBox.shrink(),
            ),
            Row(
              children: [
                Text('Recent scans', style: Theme.of(context).textTheme.titleLarge),
                const Spacer(),
                TextButton(
                  onPressed: () => context.go('/history'),
                  child: const Text('See all'),
                ),
              ],
            ),
            const SizedBox(height: 8),
            SizedBox(
              height: 128,
              child: history.when(
                loading: () => ListView.builder(
                  scrollDirection: Axis.horizontal,
                  itemCount: 3,
                  itemBuilder: (_, __) => const Padding(
                    padding: EdgeInsets.only(right: 12),
                    child: SkeletonLoader(height: 128, width: 180, radius: 16),
                  ),
                ),
                error: (e, _) => Text('$e', style: const TextStyle(color: AppColors.highRisk)),
                data: (items) {
                  if (items.isEmpty) {
                    return Container(
                      width: double.infinity,
                      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 18),
                      decoration: BoxDecoration(
                        color: AppColors.surface,
                        borderRadius: BorderRadius.circular(16),
                        border: Border.all(color: AppColors.border),
                      ),
                      child: Row(
                        children: [
                          Container(
                            padding: const EdgeInsets.all(10),
                            decoration: BoxDecoration(
                              color: AppColors.accent.withOpacity( 0.1),
                              shape: BoxShape.circle,
                            ),
                            child: const Icon(Icons.radar, color: AppColors.accent, size: 22),
                          ),
                          const SizedBox(width: 14),
                          const Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              mainAxisAlignment: MainAxisAlignment.center,
                              children: [
                                Text(
                                  'No scans yet',
                                  style: TextStyle(
                                    color: AppColors.textPrimary,
                                    fontWeight: FontWeight.w600,
                                    fontSize: 14,
                                  ),
                                ),
                                SizedBox(height: 2),
                                Text(
                                  'Search above or tap the Scan tab to analyze a package.',
                                  style: TextStyle(color: AppColors.textMuted, fontSize: 11),
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                    );
                  }
                  return ListView.builder(
                    scrollDirection: Axis.horizontal,
                    itemCount: items.length,
                    itemBuilder: (_, i) => RecentScanCard(
                      item: items[i],
                      onTap: () => context.go('/history'),
                    ),
                  );
                },
              ),
            ),
            const SizedBox(height: 28),
            Text('Risk trend', style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 4),
            const Text(
              'Estimated score from last scans (safe 15 · suspicious 45 · high 82)',
              style: TextStyle(color: AppColors.textMuted, fontSize: 12),
            ),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.fromLTRB(8, 16, 16, 8),
              decoration: BoxDecoration(
                color: AppColors.surface,
                borderRadius: BorderRadius.circular(16),
                border: Border.all(color: AppColors.border),
              ),
              child: history.when(
                loading: () => const SkeletonLoader(height: 160),
                error: (_, __) => const SizedBox(height: 160),
                data: (items) => RiskTrendChart(items: items),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
