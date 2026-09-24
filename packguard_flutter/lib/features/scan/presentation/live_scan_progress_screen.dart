import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../core/theme/app_colors.dart';
import '../application/scan_providers.dart';

/// Animated vertical pipeline. The HTTP call starts immediately; the UI
/// advances one step every ≥1.5s so students can explain the four stages
/// even when PyPI + ML finish in under a second.
class LiveScanProgressScreen extends ConsumerStatefulWidget {
  const LiveScanProgressScreen({super.key});

  @override
  ConsumerState<LiveScanProgressScreen> createState() => _LiveScanProgressScreenState();
}

class _LiveScanProgressScreenState extends ConsumerState<LiveScanProgressScreen> {
  static const _labels = [
    'Fetching metadata (PyPI JSON)',
    'Analyzing code (AST walk)',
    'Checking typosquatting (Levenshtein)',
    'Calculating risk score (Random Forest)',
  ];

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _runScan());
  }

  void _runScan() {
    ref.read(liveScanProvider.notifier).start().then((_) {
      if (!mounted) return;
      final s = ref.read(liveScanProvider);
      if (s.error == null && s.result != null) {
        // Brief 400ms pause so the student/user sees the 4th checkmark illuminate
        Future.delayed(const Duration(milliseconds: 400), () {
          if (mounted) context.go('/scan/results');
        });
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final scan = ref.watch(liveScanProvider);
    final target = ref.watch(scanInputProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Live Security Analysis'),
        leading: IconButton(
          icon: const Icon(Icons.close),
          onPressed: () => context.pop(),
        ),
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(24, 16, 24, 28),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Target Package Badge / Name
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                decoration: BoxDecoration(
                  color: AppColors.surface,
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(color: AppColors.border),
                ),
                child: Row(
                  children: [
                    Icon(
                      target.mode == ScanInputMode.package
                          ? Icons.inventory_2_outlined
                          : Icons.description_outlined,
                      color: AppColors.accent,
                      size: 24,
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            target.mode == ScanInputMode.package
                                ? target.packageName
                                : (target.fileName ?? 'requirements.txt'),
                            style: const TextStyle(
                              color: AppColors.textPrimary,
                              fontWeight: FontWeight.w700,
                              fontSize: 16,
                            ),
                          ),
                          const SizedBox(height: 2),
                          const Text(
                            'Static AST walk · typosquat score · Random Forest',
                            style: TextStyle(color: AppColors.textMuted, fontSize: 11),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 36),

              // 4-Stage Vertical Pipeline with Connecting Lines
              Expanded(
                child: ListView.builder(
                  itemCount: _labels.length,
                  itemBuilder: (context, i) {
                    final done = scan.completed.contains(i);
                    final isFailed = scan.error != null && scan.activeIndex == i;
                    final active = scan.activeIndex == i && !done && !isFailed;
                    final isLast = i == _labels.length - 1;

                    return _StepRow(
                      index: i,
                      label: _labels[i],
                      done: done,
                      active: active,
                      failed: isFailed,
                      isLast: isLast,
                    );
                  },
                ),
              ),

              // Error State Card with Action Buttons
              if (scan.error != null) ...[
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: AppColors.highRisk.withOpacity( 0.12),
                    borderRadius: BorderRadius.circular(14),
                    border: Border.all(color: AppColors.highRisk.withOpacity( 0.5)),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          const Icon(Icons.error_outline, color: AppColors.highRisk, size: 20),
                          const SizedBox(width: 8),
                          const Text(
                            'Analysis Failed',
                            style: TextStyle(
                              color: AppColors.highRisk,
                              fontWeight: FontWeight.w700,
                              fontSize: 14,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 6),
                      Text(
                        scan.error!,
                        style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
                      ),
                      const SizedBox(height: 14),
                      Row(
                        children: [
                          OutlinedButton(
                            onPressed: () => context.pop(),
                            style: OutlinedButton.styleFrom(
                              side: const BorderSide(color: AppColors.border),
                              foregroundColor: AppColors.textSecondary,
                            ),
                            child: const Text('Back to Input'),
                          ),
                          const SizedBox(width: 10),
                          ElevatedButton(
                            onPressed: _runScan,
                            style: ElevatedButton.styleFrom(
                              backgroundColor: AppColors.highRisk,
                              foregroundColor: Colors.white,
                            ),
                            child: const Text('Retry Scan'),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }
}

class _StepRow extends StatelessWidget {
  const _StepRow({
    required this.index,
    required this.label,
    required this.done,
    required this.active,
    required this.failed,
    required this.isLast,
  });

  final int index;
  final String label;
  final bool done;
  final bool active;
  final bool failed;
  final bool isLast;

  @override
  Widget build(BuildContext context) {
    return IntrinsicHeight(
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Indicator circle + connecting vertical line
          Column(
            children: [
              AnimatedContainer(
                duration: const Duration(milliseconds: 280),
                width: 36,
                height: 36,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: done
                      ? AppColors.accent.withOpacity( 0.16)
                      : failed
                          ? AppColors.highRisk.withOpacity( 0.16)
                          : active
                              ? AppColors.surfaceElevated
                              : AppColors.surface,
                  border: Border.all(
                    color: done
                        ? AppColors.accent
                        : failed
                            ? AppColors.highRisk
                            : active
                                ? AppColors.accent
                                : AppColors.border,
                    width: active || done || failed ? 1.8 : 1.2,
                  ),
                  boxShadow: active
                      ? [
                          BoxShadow(
                            color: AppColors.accent.withOpacity( 0.25),
                            blurRadius: 12,
                            spreadRadius: 1,
                          ),
                        ]
                      : [],
                ),
                child: Center(
                  child: done
                      ? const Icon(Icons.check, size: 20, color: AppColors.accent)
                      : failed
                          ? const Icon(Icons.close, size: 20, color: AppColors.highRisk)
                          : active
                              ? const SizedBox(
                                  width: 16,
                                  height: 16,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2.2,
                                    color: AppColors.accent,
                                  ),
                                )
                              : Text(
                                  '${index + 1}',
                                  style: const TextStyle(
                                    color: AppColors.textMuted,
                                    fontSize: 13,
                                    fontWeight: FontWeight.w600,
                                  ),
                                ),
                ),
              ),
              if (!isLast)
                Expanded(
                  child: Container(
                    width: 2,
                    margin: const EdgeInsets.symmetric(vertical: 4),
                    color: done ? AppColors.accent : AppColors.border,
                  ),
                ),
            ],
          ),
          const SizedBox(width: 16),

          // Step label
          Expanded(
            child: Padding(
              padding: const EdgeInsets.only(top: 8, bottom: 28),
              child: AnimatedDefaultTextStyle(
                duration: const Duration(milliseconds: 280),
                style: TextStyle(
                  fontSize: 15,
                  fontWeight: done || active ? FontWeight.w600 : FontWeight.w400,
                  color: done
                      ? AppColors.accent
                      : failed
                          ? AppColors.highRisk
                          : active
                              ? AppColors.textPrimary
                              : AppColors.textMuted,
                ),
                child: Text(label),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
