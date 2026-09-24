import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/network/api_result.dart';
import '../../scan/data/models/scan_models.dart';
import '../../scan/data/scan_repository.dart';

/// Fetches the recursive dependency tree for a given package name.
final dependencyGraphProvider =
    FutureProvider.family<DependencyGraphData, String>((ref, packageName) async {
  final repo = ref.watch(scanRepositoryProvider);
  final res = await repo.getDependencyGraph(packageName);

  if (res is ApiSuccess<DependencyGraphData>) {
    return res.data;
  } else if (res is ApiFailure<DependencyGraphData>) {
    throw Exception(res.message);
  }
  throw Exception('Unknown error building dependency graph');
});
