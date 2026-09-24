import 'dart:convert';
import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../../../core/constants/api_endpoints.dart';
import '../../../core/network/api_result.dart';
import '../../../core/network/dio_client.dart';
import 'models/scan_models.dart';

class ScanRepository {
  ScanRepository(this._dio);
  final Dio _dio;

  Future<ApiResult<List<PackageSuggestion>>> searchPackages(String query) async {
    try {
      final res = await _dio.get(
        ApiEndpoints.packageSearch,
        queryParameters: {'q': query, 'limit': 8},
      );
      final results = (res.data['results'] as List<dynamic>? ?? [])
          .map((e) => PackageSuggestion.fromJson(e as Map<String, dynamic>))
          .toList();
      return ApiSuccess(results);
    } on DioException catch (e) {
      return ApiFailure(e.message ?? 'Search failed', statusCode: e.response?.statusCode);
    }
  }

  Future<ApiResult<ScanResult>> scanPackage(String packageName) async {
    try {
      final res = await _dio.post(
        ApiEndpoints.scanPackage,
        data: {'packageName': packageName},
        options: Options(contentType: Headers.jsonContentType),
      );
      return ApiSuccess(ScanResult.fromJson(res.data as Map<String, dynamic>));
    } on DioException catch (e) {
      return ApiFailure(_message(e), statusCode: e.response?.statusCode);
    }
  }

  Future<ApiResult<ScanResult>> scanRequirementsFile({
    String? path,
    List<int>? bytes,
    required String filename,
  }) async {
    try {
      final MultipartFile multipart;
      if (bytes != null) {
        multipart = MultipartFile.fromBytes(bytes, filename: filename);
      } else if (path != null) {
        multipart = await MultipartFile.fromFile(path, filename: filename);
      } else {
        return const ApiFailure('No file data provided');
      }

      final form = FormData.fromMap({
        'requirements_file': multipart,
      });
      final res = await _dio.post(ApiEndpoints.scanPackage, data: form);
      final data = res.data as Map<String, dynamic>;
      // Batch response: { scanId, results: [...], packageCount }
      if (data['results'] is List && (data['results'] as List).isNotEmpty) {
        final first = ScanResult.fromJson(
          (data['results'] as List).first as Map<String, dynamic>,
        );
        return ApiSuccess(
          ScanResult(
            packageName: filename,
            packageVersion: '${data['packageCount']} packages',
            riskScore: first.riskScore,
            riskLabel: first.riskLabel,
            explanation: first.explanation,
            dependencyTree: first.dependencyTree,
            timestamp: first.timestamp,
            scanId: data['scanId'] as String? ?? first.scanId,
          ),
        );
      }
      return ApiSuccess(ScanResult.fromJson(data));
    } on DioException catch (e) {
      return ApiFailure(_message(e), statusCode: e.response?.statusCode);
    }
  }

  Future<ApiResult<List<HistoryItem>>> fetchHistory({int limit = 20, String? riskLevel}) async {
    try {
      final query = <String, dynamic>{'limit': limit};
      if (riskLevel != null && riskLevel.isNotEmpty && riskLevel != 'all') {
        query['riskLevel'] = riskLevel;
      }
      final res = await _dio.get(
        ApiEndpoints.scanHistory,
        queryParameters: query,
      );
      final items = (res.data['items'] as List<dynamic>? ?? [])
          .map((e) => HistoryItem.fromJson(e as Map<String, dynamic>))
          .toList();
      // Cache latest results for offline viewing
      await cacheHistory(items);
      return ApiSuccess(items);
    } on DioException catch (e) {
      // Offline fallback: load cached items
      final cached = await getCachedHistory();
      if (cached.isNotEmpty) {
        return ApiSuccess(cached);
      }
      return ApiFailure(e.message ?? 'History failed', statusCode: e.response?.statusCode);
    } catch (_) {
      final cached = await getCachedHistory();
      if (cached.isNotEmpty) return ApiSuccess(cached);
      return const ApiFailure('Failed to load history');
    }
  }

  /// Fetches dependency graph for visualization
  Future<ApiResult<DependencyGraphData>> getDependencyGraph(
    String packageName, {
    String? version,
    int? maxDepth,
  }) async {
    try {
      final query = <String, dynamic>{};
      if (version != null) query['version'] = version;
      if (maxDepth != null) query['maxDepth'] = maxDepth;

      final res = await _dio.get(
        ApiEndpoints.dependencyGraph(packageName),
        queryParameters: query,
      );
      return ApiSuccess(DependencyGraphData.fromJson(res.data as Map<String, dynamic>));
    } on DioException catch (e) {
      return ApiFailure(_message(e), statusCode: e.response?.statusCode);
    } catch (e) {
      return ApiFailure('Failed to build graph: $e');
    }
  }

  /// Downloads PDF report bytes
  Future<ApiResult<List<int>>> downloadPdfReport(String scanId) async {
    try {
      final res = await _dio.get<List<int>>(
        ApiEndpoints.scanReportPdf(scanId),
        options: Options(responseType: ResponseType.bytes),
      );
      if (res.data != null) {
        return ApiSuccess(res.data!);
      }
      return const ApiFailure('Empty report received');
    } on DioException catch (e) {
      return ApiFailure(_message(e), statusCode: e.response?.statusCode);
    } catch (e) {
      return ApiFailure('Failed to download report: $e');
    }
  }

  /// Triggers or retrieves rescan check for monitored packages
  Future<ApiResult<RescanCheckResult>> checkRescan({bool runSync = true}) async {
    try {
      final res = await _dio.post(
        ApiEndpoints.rescanCheck,
        queryParameters: {'run_sync': runSync},
      );
      return ApiSuccess(RescanCheckResult.fromJson(res.data as Map<String, dynamic>));
    } on DioException catch (e) {
      return ApiFailure(_message(e), statusCode: e.response?.statusCode);
    } catch (e) {
      return ApiFailure('Failed to check rescan: $e');
    }
  }

  /// Offline Cache: Save history items to SharedPreferences
  Future<void> cacheHistory(List<HistoryItem> items) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final jsonList = items.map((i) => jsonEncode(i.toJson())).toList();
      await prefs.setStringList('cached_scan_history', jsonList);
    } catch (_) {}
  }

  /// Offline Cache: Read history items from SharedPreferences
  Future<List<HistoryItem>> getCachedHistory() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final list = prefs.getStringList('cached_scan_history') ?? [];
      return list.map((str) => HistoryItem.fromJson(jsonDecode(str) as Map<String, dynamic>)).toList();
    } catch (_) {
      return [];
    }
  }

  String _message(DioException e) {
    final data = e.response?.data;
    if (data is Map && data['detail'] != null) return data['detail'].toString();
    return e.message ?? 'Scan failed';
  }
}

final scanRepositoryProvider = Provider<ScanRepository>((ref) {
  return ScanRepository(ref.watch(dioProvider));
});
