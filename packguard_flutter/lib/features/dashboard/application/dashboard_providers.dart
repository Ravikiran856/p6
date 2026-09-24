import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/network/api_result.dart';
import '../../scan/data/models/scan_models.dart';
import '../../scan/data/scan_repository.dart';

final dashboardHistoryProvider = FutureProvider.autoDispose<List<HistoryItem>>((ref) async {
  final result = await ref.watch(scanRepositoryProvider).fetchHistory(limit: 12);
  if (result is ApiSuccess<List<HistoryItem>>) {
    return result.data;
  }
  return const [];
});

/// Fetches rescan results and filters for any package with newly detected CVEs
final dashboardRescanAlertsProvider = FutureProvider.autoDispose<List<RescanAlertData>>((ref) async {
  final result = await ref.watch(scanRepositoryProvider).checkRescan(runSync: true);
  if (result is ApiSuccess<RescanCheckResult>) {
    return result.data.alerts.where((a) => a.knownVulnerabilities.isNotEmpty).toList();
  }
  return const [];
});
