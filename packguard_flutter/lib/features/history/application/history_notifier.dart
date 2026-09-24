import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/network/api_result.dart';
import '../../scan/data/models/scan_models.dart';
import '../../scan/data/scan_repository.dart';

class HistoryState {
  const HistoryState({
    this.items = const [],
    this.activeFilter = 'all',
    this.isLoading = false,
    this.isOffline = false,
    this.hasMore = true,
    this.error,
  });

  final List<HistoryItem> items;
  final String activeFilter;
  final bool isLoading;
  final bool isOffline;
  final bool hasMore;
  final String? error;

  HistoryState copyWith({
    List<HistoryItem>? items,
    String? activeFilter,
    bool? isLoading,
    bool? isOffline,
    bool? hasMore,
    String? error,
  }) {
    return HistoryState(
      items: items ?? this.items,
      activeFilter: activeFilter ?? this.activeFilter,
      isLoading: isLoading ?? this.isLoading,
      isOffline: isOffline ?? this.isOffline,
      hasMore: hasMore ?? this.hasMore,
      error: error,
    );
  }
}

class HistoryNotifier extends Notifier<HistoryState> {
  static const int _pageSize = 20;

  @override
  HistoryState build() {
    // Initial fetch on build
    Future.microtask(() => loadHistory(refresh: true));
    return const HistoryState(isLoading: true);
  }

  Future<void> setFilter(String filter) async {
    if (state.activeFilter == filter) return;
    state = state.copyWith(activeFilter: filter, isLoading: true, items: []);
    await loadHistory(refresh: true);
  }

  Future<void> loadHistory({bool refresh = false}) async {
    final repo = ref.read(scanRepositoryProvider);
    final currentCount = refresh ? 0 : state.items.length;
    final filter = state.activeFilter == 'all' ? null : state.activeFilter;

    if (!refresh && (state.isLoading || !state.hasMore)) return;

    state = state.copyWith(isLoading: true, error: null);

    final res = await repo.fetchHistory(
      limit: currentCount + _pageSize,
      riskLevel: filter,
    );

    if (res is ApiSuccess<List<HistoryItem>>) {
      final fetched = res.data;
      final filtered = filter == null
          ? fetched
          : fetched.where((i) => i.overallRiskLevel == filter).toList();

      state = state.copyWith(
        items: filtered,
        isLoading: false,
        isOffline: false,
        hasMore: fetched.length >= currentCount + _pageSize,
      );
    } else if (res is ApiFailure<List<HistoryItem>>) {
      // Check offline cache
      final cached = await repo.getCachedHistory();
      if (cached.isNotEmpty) {
        final filtered = filter == null
            ? cached
            : cached.where((i) => i.overallRiskLevel == filter).toList();
        state = state.copyWith(
          items: filtered,
          isLoading: false,
          isOffline: true,
          hasMore: false,
        );
      } else {
        state = state.copyWith(
          isLoading: false,
          error: res.message,
          hasMore: false,
        );
      }
    }
  }
}

final historyNotifierProvider =
    NotifierProvider<HistoryNotifier, HistoryState>(HistoryNotifier.new);
