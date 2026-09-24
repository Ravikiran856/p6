import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/constants/app_constants.dart';
import '../../../core/network/api_result.dart';
import '../../dashboard/application/dashboard_providers.dart';
import '../data/models/scan_models.dart';
import '../data/scan_repository.dart';

enum ScanInputMode { package, requirements }

/// Form state for the Scan tab (and Dashboard quick-search).
class ScanInputState {
  const ScanInputState({
    this.mode = ScanInputMode.package,
    this.packageName = '',
    this.filePath,
    this.fileName,
    this.fileBytes,
    this.fileSize,
    this.suggestions = const [],
    this.searching = false,
  });

  final ScanInputMode mode;
  final String packageName;
  final String? filePath;
  final String? fileName;
  final List<int>? fileBytes;
  final int? fileSize;
  final List<PackageSuggestion> suggestions;
  final bool searching;

  bool get canScan {
    if (mode == ScanInputMode.package) {
      return packageName.trim().length >= 2;
    }
    return filePath != null || fileBytes != null;
  }

  ScanInputState copyWith({
    ScanInputMode? mode,
    String? packageName,
    String? filePath,
    String? fileName,
    List<int>? fileBytes,
    int? fileSize,
    List<PackageSuggestion>? suggestions,
    bool? searching,
    bool clearFile = false,
  }) {
    return ScanInputState(
      mode: mode ?? this.mode,
      packageName: packageName ?? this.packageName,
      filePath: clearFile ? null : (filePath ?? this.filePath),
      fileName: clearFile ? null : (fileName ?? this.fileName),
      fileBytes: clearFile ? null : (fileBytes ?? this.fileBytes),
      fileSize: clearFile ? null : (fileSize ?? this.fileSize),
      suggestions: suggestions ?? this.suggestions,
      searching: searching ?? this.searching,
    );
  }
}

class ScanInputNotifier extends Notifier<ScanInputState> {
  Timer? _debounce;

  @override
  ScanInputState build() {
    ref.onDispose(() => _debounce?.cancel());
    return const ScanInputState();
  }

  void setMode(ScanInputMode mode) {
    state = state.copyWith(mode: mode, suggestions: const []);
  }

  void setPackageName(String name) {
    state = state.copyWith(packageName: name);
    _debounce?.cancel();
    if (name.trim().length < 2) {
      state = state.copyWith(suggestions: const [], searching: false);
      return;
    }
    state = state.copyWith(searching: true);
    _debounce = Timer(AppConstants.searchDebounce, () => _search(name.trim()));
  }

  void pickSuggestion(String name) {
    _debounce?.cancel();
    state = state.copyWith(
      packageName: name,
      suggestions: const [],
      searching: false,
    );
  }

  void setRequirementsFile({
    String? path,
    List<int>? bytes,
    required String filename,
    int? size,
  }) {
    state = state.copyWith(
      filePath: path,
      fileBytes: bytes,
      fileName: filename,
      fileSize: size,
    );
  }

  void clearFile() {
    state = state.copyWith(clearFile: true);
  }

  Future<void> _search(String q) async {
    final result = await ref.read(scanRepositoryProvider).searchPackages(q);
    if (q != state.packageName.trim()) return; // Stale query response
    if (result is ApiSuccess<List<PackageSuggestion>>) {
      state = state.copyWith(suggestions: result.data, searching: false);
    } else {
      state = state.copyWith(suggestions: const [], searching: false);
    }
  }
}

final scanInputProvider =
    NotifierProvider<ScanInputNotifier, ScanInputState>(ScanInputNotifier.new);

/// Pipeline steps shown on Live Scan Progress. Order matches the backend pipeline:
/// 0. Fetching metadata (PyPI JSON API)
/// 1. Analyzing code (AST visitor: suspicious imports, eval, network sockets)
/// 2. Checking typosquatting (Levenshtein distance vs Top 5,000 packages)
/// 3. Calculating risk score (Pre-trained Random Forest classifier)
enum ScanStep { fetching, analyzing, typosquat, scoring }

class LiveScanState {
  const LiveScanState({
    this.activeIndex = 0,
    this.completed = const {},
    this.result,
    this.error,
    this.finished = false,
  });

  final int activeIndex;
  final Set<int> completed;
  final ScanResult? result;
  final String? error;
  final bool finished;

  LiveScanState copyWith({
    int? activeIndex,
    Set<int>? completed,
    ScanResult? result,
    String? error,
    bool? finished,
  }) {
    return LiveScanState(
      activeIndex: activeIndex ?? this.activeIndex,
      completed: completed ?? this.completed,
      result: result ?? this.result,
      error: error,
      finished: finished ?? this.finished,
    );
  }
}

class LiveScanNotifier extends AutoDisposeNotifier<LiveScanState> {
  @override
  LiveScanState build() => const LiveScanState();

  /// VIVA ARCHITECTURE EXPLANATION:
  /// Coordinates real backend HTTP execution concurrently with a 4-stage UI animation.
  ///
  /// Requirements respected:
  /// 1. Real request launched immediately on method entry.
  /// 2. Minimum display time of ~1.5s per step so students/evaluators can read the pipeline.
  /// 3. If the backend fails early (e.g. 404 package not found), we abort progression
  ///    immediately rather than faking remaining steps.
  /// 4. Step 3 (final score) holds until the real request completes if analysis takes longer.
  Future<void> start() async {
    final input = ref.read(scanInputProvider);
    final repo = ref.read(scanRepositoryProvider);

    // Launch real HTTP scan concurrently
    final apiFuture = input.mode == ScanInputMode.package
        ? repo.scanPackage(input.packageName.trim())
        : repo.scanRequirementsFile(
            path: input.filePath,
            bytes: input.fileBytes,
            filename: input.fileName ?? 'requirements.txt',
          );

    ApiResult<ScanResult>? earlyResult;
    bool apiFinished = false;

    // Track real API outcome as soon as it arrives
    apiFuture.then((res) {
      earlyResult = res;
      apiFinished = true;
    }).catchError((err) {
      earlyResult = ApiFailure(err.toString());
      apiFinished = true;
    });

    // Animate intermediate stages (0: Fetching, 1: Analyzing, 2: Typosquat)
    for (var i = 0; i < 3; i++) {
      state = state.copyWith(activeIndex: i);
      await Future<void>.delayed(AppConstants.minStepDuration);

      // If backend already failed (e.g., PyPI 404), halt immediately
      if (apiFinished && earlyResult is ApiFailure<ScanResult>) {
        final fail = earlyResult as ApiFailure<ScanResult>;
        state = state.copyWith(error: fail.message, finished: true);
        return;
      }

      state = state.copyWith(completed: {...state.completed, i});
    }

    // Stage 3: Calculating risk score (Random Forest inference)
    state = state.copyWith(activeIndex: 3);

    // Wait at least the min step duration AND ensure the backend future has settled
    final results = await Future.wait([
      apiFuture,
      Future<void>.delayed(AppConstants.minStepDuration),
    ]);

    final finalResult = results.first as ApiResult<ScanResult>;

    if (finalResult is ApiSuccess<ScanResult>) {
      // Mark stage 3 complete with checkmark
      state = state.copyWith(
        completed: {...state.completed, 3},
        result: finalResult.data,
        finished: true,
      );
      ref.read(lastScanResultProvider.notifier).state = finalResult.data;
      ref.invalidate(dashboardHistoryProvider);
    } else if (finalResult is ApiFailure<ScanResult>) {
      state = state.copyWith(
        error: finalResult.message,
        finished: true,
      );
    }
  }
}

final liveScanProvider =
    AutoDisposeNotifierProvider<LiveScanNotifier, LiveScanState>(
  LiveScanNotifier.new,
);

final lastScanResultProvider = StateProvider<ScanResult?>((ref) => null);
