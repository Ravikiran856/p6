import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../../../core/theme/app_colors.dart';
import '../../../core/widgets/risk_badge.dart';
import '../../../core/widgets/skeleton_loader.dart';
import '../../../shared_models/risk_level.dart';
import '../../scan/application/scan_providers.dart';
import '../../scan/data/models/scan_models.dart';
import '../application/history_notifier.dart';

/// Full Scan History Screen with Filters, Infinite Scrolling, and Offline Caching
///
/// VIVA ARCHITECTURE EXPLANATION:
/// 1. Dual Data Sources: Uses online REST `/scan/history` when connected, and gracefully
///    degrades to SharedPreferences local cache when offline, displaying an offline banner.
/// 2. Reactive Filters: Client/server coordinated filtering for Safe / Suspicious / High Risk.
/// 3. Hero Transitions & Haptics: Tapping items transitions seamlessly into the Results Screen.
class ScanHistoryScreen extends ConsumerStatefulWidget {
  const ScanHistoryScreen({super.key});

  @override
  ConsumerState<ScanHistoryScreen> createState() => _ScanHistoryScreenState();
}

class _ScanHistoryScreenState extends ConsumerState<ScanHistoryScreen> {
  final ScrollController _scrollController = ScrollController();

  @override
  void initState() {
    super.initState();
    _scrollController.addListener(_onScroll);
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  void _onScroll() {
    if (_scrollController.position.pixels >=
        _scrollController.position.maxScrollExtent - 200) {
      ref.read(historyNotifierProvider.notifier).loadHistory();
    }
  }

  void _openResult(HistoryItem item) {
    final level = RiskLevel.fromApi(item.overallRiskLevel);
    if (level == RiskLevel.highRisk) {
      HapticFeedback.heavyImpact();
    } else {
      HapticFeedback.selectionClick();
    }

    // Populate lastScanResultProvider so Results screen renders this item immediately
    ref.read(lastScanResultProvider.notifier).state = ScanResult(
      packageName: item.displayName,
      packageVersion: item.type == 'requirements_file' ? '${item.packageCount} pkgs' : '1.0.0',
      riskScore: level.estimatedScore,
      riskLabel: item.overallRiskLevel ?? 'unknown',
      explanation: [
        'Audit record loaded from historical analysis logs.',
        'Initial scan conducted on ${item.createdAt}.',
      ],
      dependencyTree: [],
      timestamp: item.createdAt,
      scanId: item.scanId,
    );

    context.push('/scan/results');
  }

  @override
  Widget build(BuildContext context) {
    final history = ref.watch(historyNotifierProvider);
    final notifier = ref.read(historyNotifierProvider.notifier);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Scan History'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh',
            onPressed: () => notifier.loadHistory(refresh: true),
          ),
        ],
      ),
      body: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Offline Warning Banner
            if (history.isOffline)
              Container(
                width: double.infinity,
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                color: AppColors.suspicious.withOpacity( 0.15),
                child: const Row(
                  children: [
                    Icon(Icons.cloud_off, size: 16, color: AppColors.suspicious),
                    SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'Showing offline cached scans (Network unavailable)',
                        style: TextStyle(color: AppColors.suspicious, fontSize: 12, fontWeight: FontWeight.w600),
                      ),
                    ),
                  ],
                ),
              ),

            // Filter Chips Bar
            Container(
              padding: const EdgeInsets.fromLTRB(16, 12, 16, 12),
              child: SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                child: Row(
                  children: [
                    _filterChip('all', 'All Scans', history.activeFilter, notifier.setFilter),
                    const SizedBox(width: 8),
                    _filterChip('safe', 'Safe', history.activeFilter, notifier.setFilter, color: AppColors.safe),
                    const SizedBox(width: 8),
                    _filterChip('suspicious', 'Suspicious', history.activeFilter, notifier.setFilter, color: AppColors.suspicious),
                    const SizedBox(width: 8),
                    _filterChip('high_risk', 'High Risk', history.activeFilter, notifier.setFilter, color: AppColors.highRisk),
                  ],
                ),
              ),
            ),

            // List of Scans
            Expanded(
              child: RefreshIndicator(
                color: AppColors.accent,
                onRefresh: () => notifier.loadHistory(refresh: true),
                child: history.isLoading && history.items.isEmpty
                    ? ListView.builder(
                        padding: const EdgeInsets.all(16),
                        itemCount: 5,
                        itemBuilder: (_, __) => const Padding(
                          padding: EdgeInsets.only(bottom: 12),
                          child: SkeletonLoader(height: 76, radius: 14),
                        ),
                      )
                    : history.items.isEmpty
                        ? Center(
                            child: Column(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                const Icon(Icons.history_toggle_off, size: 48, color: AppColors.textMuted),
                                const SizedBox(height: 12),
                                Text(
                                  history.activeFilter == 'all'
                                      ? 'No scan records found.'
                                      : 'No "${history.activeFilter}" scans found.',
                                  style: const TextStyle(color: AppColors.textMuted),
                                ),
                              ],
                            ),
                          )
                        : ListView.builder(
                            controller: _scrollController,
                            padding: const EdgeInsets.fromLTRB(16, 4, 16, 24),
                            itemCount: history.items.length + (history.hasMore ? 1 : 0),
                            itemBuilder: (context, i) {
                              if (i == history.items.length) {
                                return const Center(
                                  child: Padding(
                                    padding: EdgeInsets.symmetric(vertical: 16),
                                    child: CircularProgressIndicator(color: AppColors.accent, strokeWidth: 2),
                                  ),
                                );
                              }

                              final item = history.items[i];
                              final isFile = item.type == 'requirements_file';
                              final riskLevel = RiskLevel.fromApi(item.overallRiskLevel);

                              DateTime? when;
                              try {
                                when = DateTime.tryParse(item.createdAt);
                              } catch (_) {}
                              final stamp = when == null
                                  ? item.createdAt
                                  : DateFormat.yMMMd().add_jm().format(when.toLocal());

                              return Container(
                                margin: const EdgeInsets.only(bottom: 10),
                                decoration: BoxDecoration(
                                  color: AppColors.surface,
                                  borderRadius: BorderRadius.circular(14),
                                  border: Border.all(color: AppColors.border),
                                ),
                                child: Material(
                                  color: Colors.transparent,
                                  child: InkWell(
                                    borderRadius: BorderRadius.circular(14),
                                    onTap: () => _openResult(item),
                                    child: Padding(
                                      padding: const EdgeInsets.all(14),
                                      child: Row(
                                        children: [
                                          Container(
                                            padding: const EdgeInsets.all(10),
                                            decoration: BoxDecoration(
                                              color: AppColors.surfaceElevated,
                                              shape: BoxShape.circle,
                                            ),
                                            child: Icon(
                                              isFile ? Icons.description_outlined : Icons.inventory_2_outlined,
                                              color: AppColors.accent,
                                              size: 20,
                                            ),
                                          ),
                                          const SizedBox(width: 14),
                                          Expanded(
                                            child: Column(
                                              crossAxisAlignment: CrossAxisAlignment.start,
                                              children: [
                                                Hero(
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
                                                const SizedBox(height: 3),
                                                Text(
                                                  stamp,
                                                  style: const TextStyle(
                                                    color: AppColors.textMuted,
                                                    fontSize: 12,
                                                  ),
                                                ),
                                              ],
                                            ),
                                          ),
                                          const SizedBox(width: 10),
                                          RiskBadge(level: riskLevel, compact: true),
                                          const SizedBox(width: 6),
                                          const Icon(Icons.chevron_right, size: 18, color: AppColors.textMuted),
                                        ],
                                      ),
                                    ),
                                  ),
                                ),
                              );
                            },
                          ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _filterChip(
    String filterKey,
    String label,
    String activeFilter,
    ValueChanged<String> onSelected, {
    Color? color,
  }) {
    final isSelected = activeFilter == filterKey;
    final chipColor = color ?? AppColors.accent;

    return GestureDetector(
      onTap: () => onSelected(filterKey),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 180),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 7),
        decoration: BoxDecoration(
          color: isSelected ? chipColor.withOpacity( 0.16) : AppColors.surface,
          borderRadius: BorderRadius.circular(20),
          border: Border.all(
            color: isSelected ? chipColor : AppColors.border,
            width: isSelected ? 1.4 : 1.0,
          ),
        ),
        child: Text(
          label,
          style: TextStyle(
            color: isSelected ? chipColor : AppColors.textSecondary,
            fontSize: 12,
            fontWeight: isSelected ? FontWeight.w700 : FontWeight.w500,
          ),
        ),
      ),
    );
  }
}
