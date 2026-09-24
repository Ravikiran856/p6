class PackageSuggestion {
  const PackageSuggestion({
    required this.name,
    this.latestVersion,
    this.isKnownTop5000 = true,
  });

  final String name;
  final String? latestVersion;
  final bool isKnownTop5000;

  factory PackageSuggestion.fromJson(Map<String, dynamic> json) {
    return PackageSuggestion(
      name: json['name'] as String,
      latestVersion: json['latestVersion'] as String?,
      isKnownTop5000: json['isKnownTop5000'] as bool? ?? true,
    );
  }
}

class ScanFinding {
  const ScanFinding({
    required this.indicatorId,
    required this.category,
    required this.lineNumber,
    required this.codeSnippet,
    required this.filePath,
    this.title,
    this.severity,
  });

  final String indicatorId;
  final String category;
  final int lineNumber;
  final String codeSnippet;
  final String filePath;
  final String? title;
  final String? severity;

  factory ScanFinding.fromJson(Map<String, dynamic> json) {
    return ScanFinding(
      indicatorId: (json['indicatorId'] ?? json['indicator_id'] ?? '') as String,
      category: (json['category'] ?? 'Execution') as String,
      lineNumber: (json['lineNumber'] ?? json['line_number'] ?? 0) as int,
      codeSnippet: (json['codeSnippet'] ?? json['code_snippet'] ?? '') as String,
      filePath: (json['filePath'] ?? json['file_path'] ?? '') as String,
      title: json['title'] as String?,
      severity: json['severity'] as String?,
    );
  }

  Map<String, dynamic> toJson() => {
        'indicatorId': indicatorId,
        'category': category,
        'lineNumber': lineNumber,
        'codeSnippet': codeSnippet,
        'filePath': filePath,
        if (title != null) 'title': title,
        if (severity != null) 'severity': severity,
      };
}

class KnownVulnerability {
  const KnownVulnerability({
    required this.cveId,
    required this.severity,
    required this.summary,
    this.fixedVersion,
  });

  final String cveId;
  final String severity;
  final String summary;
  final String? fixedVersion;

  factory KnownVulnerability.fromJson(Map<String, dynamic> json) {
    return KnownVulnerability(
      cveId: (json['cveId'] ?? json['cve_id'] ?? '') as String,
      severity: (json['severity'] ?? 'UNKNOWN') as String,
      summary: (json['summary'] ?? '') as String,
      fixedVersion: (json['fixedVersion'] ?? json['fixed_version']) as String?,
    );
  }

  Map<String, dynamic> toJson() => {
        'cveId': cveId,
        'severity': severity,
        'summary': summary,
        if (fixedVersion != null) 'fixedVersion': fixedVersion,
      };
}

class SlopsquatAnalysisData {
  const SlopsquatAnalysisData({
    required this.isPossibleSlopsquat,
    required this.confidence,
    required this.reason,
    this.detectionMethod = 'heuristic_proxy',
  });

  final bool isPossibleSlopsquat;
  final int confidence;
  final String reason;
  final String detectionMethod;

  factory SlopsquatAnalysisData.fromJson(Map<String, dynamic> json) {
    return SlopsquatAnalysisData(
      isPossibleSlopsquat: (json['isPossibleSlopsquat'] ?? json['is_possible_slopsquat'] ?? false) as bool,
      confidence: ((json['confidence'] ?? 0) as num).toInt(),
      reason: (json['reason'] ?? '') as String,
      detectionMethod: (json['detectionMethod'] ?? json['detection_method'] ?? 'heuristic_proxy') as String,
    );
  }

  Map<String, dynamic> toJson() => {
        'isPossibleSlopsquat': isPossibleSlopsquat,
        'confidence': confidence,
        'reason': reason,
        'detectionMethod': detectionMethod,
      };
}

class ScanResult {
  const ScanResult({
    required this.packageName,
    this.packageVersion,
    required this.riskScore,
    required this.riskLabel,
    required this.explanation,
    this.findings = const [],
    this.knownVulnerabilities = const [],
    this.cveLookupStatus = 'ok',
    this.slopsquatAnalysis,
    required this.dependencyTree,
    required this.timestamp,
    this.scanId,
  });

  final String packageName;
  final String? packageVersion;
  final double riskScore;
  final String riskLabel;
  final List<String> explanation;
  final List<ScanFinding> findings;
  final List<KnownVulnerability> knownVulnerabilities;
  final String cveLookupStatus;
  final SlopsquatAnalysisData? slopsquatAnalysis;
  final List<String> dependencyTree;
  final String timestamp;
  final String? scanId;

  factory ScanResult.fromJson(Map<String, dynamic> json) {
    return ScanResult(
      packageName: (json['packageName'] ?? json['package_name'] ?? '') as String,
      packageVersion: (json['packageVersion'] ?? json['package_version']) as String?,
      riskScore: ((json['riskScore'] ?? json['risk_score'] ?? 0) as num).toDouble(),
      riskLabel: (json['riskLabel'] ?? json['risk_label'] ?? 'unknown') as String,
      explanation: (json['explanation'] as List<dynamic>? ?? [])
          .map((e) => e.toString())
          .toList(),
      findings: (json['findings'] as List<dynamic>? ?? [])
          .map((e) => ScanFinding.fromJson(e as Map<String, dynamic>))
          .toList(),
      knownVulnerabilities: (json['knownVulnerabilities'] as List<dynamic>? ??
              json['known_vulnerabilities'] as List<dynamic>? ??
              [])
          .map((e) => KnownVulnerability.fromJson(e as Map<String, dynamic>))
          .toList(),
      cveLookupStatus: (json['cveLookupStatus'] ?? json['cve_lookup_status'] ?? 'ok') as String,
      slopsquatAnalysis: json['slopsquatAnalysis'] != null
          ? SlopsquatAnalysisData.fromJson(json['slopsquatAnalysis'] as Map<String, dynamic>)
          : (json['slopsquat_analysis'] != null
              ? SlopsquatAnalysisData.fromJson(json['slopsquat_analysis'] as Map<String, dynamic>)
              : null),
      dependencyTree: ((json['dependencyTree'] ?? json['dependency_tree']) as List<dynamic>? ?? [])
          .map((e) => e.toString())
          .toList(),
      timestamp: (json['timestamp'] ?? json['createdAt'] ?? '') as String,
      scanId: (json['scanId'] ?? json['scan_id']) as String?,
    );
  }

  Map<String, dynamic> toJson() => {
        'packageName': packageName,
        'packageVersion': packageVersion,
        'riskScore': riskScore,
        'riskLabel': riskLabel,
        'explanation': explanation,
        'findings': findings.map((f) => f.toJson()).toList(),
        'knownVulnerabilities': knownVulnerabilities.map((v) => v.toJson()).toList(),
        'cveLookupStatus': cveLookupStatus,
        'slopsquatAnalysis': slopsquatAnalysis?.toJson(),
        'dependencyTree': dependencyTree,
        'timestamp': timestamp,
        'scanId': scanId,
      };
}

class HistoryItem {
  const HistoryItem({
    required this.scanId,
    required this.type,
    this.inputPackageName,
    this.inputFileName,
    this.overallRiskLevel,
    required this.createdAt,
    this.packageCount = 1,
  });

  final String scanId;
  final String type;
  final String? inputPackageName;
  final String? inputFileName;
  final String? overallRiskLevel;
  final String createdAt;
  final int packageCount;

  String get displayName =>
      inputPackageName ?? inputFileName ?? 'Scan ${scanId.substring(0, scanId.length >= 8 ? 8 : scanId.length)}';

  factory HistoryItem.fromJson(Map<String, dynamic> json) {
    return HistoryItem(
      scanId: (json['scanId'] ?? json['scan_id'] ?? '') as String,
      type: (json['type'] ?? 'single_package') as String,
      inputPackageName: (json['inputPackageName'] ?? json['input_package_name']) as String?,
      inputFileName: (json['inputFileName'] ?? json['input_file_name']) as String?,
      overallRiskLevel: (json['overallRiskLevel'] ?? json['overall_risk_level']) as String?,
      createdAt: (json['createdAt'] ?? json['created_at'] ?? '') as String,
      packageCount: (json['packageCount'] ?? json['package_count'] ?? 1) as int,
    );
  }

  Map<String, dynamic> toJson() => {
        'scanId': scanId,
        'type': type,
        'inputPackageName': inputPackageName,
        'inputFileName': inputFileName,
        'overallRiskLevel': overallRiskLevel,
        'createdAt': createdAt,
        'packageCount': packageCount,
      };
}

/// Represents a single node in the dependency graph
class GraphNodeData {
  const GraphNodeData({
    required this.id,
    required this.label,
    required this.packageName,
    required this.version,
    required this.riskLevel,
    required this.riskScore,
    required this.riskColor,
    this.inDegree = 0,
    this.degreeCentrality = 0.0,
    this.depthInTree = 0,
    this.criticalityLabel = 'Low',
    this.blastRadiusScope = 'local blast radius within 3 levels',
  });

  final String id;
  final String label;
  final String packageName;
  final String version;
  final String riskLevel;
  final double riskScore;
  final String riskColor;
  final int inDegree;
  final double degreeCentrality;
  final int depthInTree;
  final String criticalityLabel;
  final String blastRadiusScope;

  factory GraphNodeData.fromJson(Map<String, dynamic> json) {
    return GraphNodeData(
      id: (json['id'] ?? '') as String,
      label: (json['label'] ?? json['packageName'] ?? json['package_name'] ?? '') as String,
      packageName: (json['packageName'] ?? json['package_name'] ?? json['label'] ?? '') as String,
      version: (json['version'] ?? 'latest') as String,
      riskLevel: (json['riskLevel'] ?? json['risk_level'] ?? 'unknown') as String,
      riskScore: ((json['riskScore'] ?? json['risk_score'] ?? 0.0) as num).toDouble(),
      riskColor: (json['risk_color'] ?? json['riskColor'] ?? '#00FF9C') as String,
      inDegree: (json['inDegree'] ?? json['in_degree'] ?? 0) as int,
      degreeCentrality: ((json['degreeCentrality'] ?? json['degree_centrality'] ?? 0.0) as num).toDouble(),
      depthInTree: (json['depthInTree'] ?? json['depth_in_tree'] ?? 0) as int,
      criticalityLabel: (json['criticalityLabel'] ?? json['criticality_label'] ?? 'Low') as String,
      blastRadiusScope: (json['blastRadiusScope'] ?? json['blast_radius_scope'] ?? 'local blast radius within 3 levels') as String,
    );
  }
}

/// Represents a directed edge between dependencies
class GraphEdgeData {
  const GraphEdgeData({required this.source, required this.target});
  final String source;
  final String target;

  factory GraphEdgeData.fromJson(Map<String, dynamic> json) {
    return GraphEdgeData(
      source: (json['source'] ?? '') as String,
      target: (json['target'] ?? '') as String,
    );
  }
}

/// Complete response from `/scan/dependency-graph/{packageName}`
class DependencyGraphData {
  const DependencyGraphData({
    required this.graphId,
    required this.rootPackage,
    required this.rootVersion,
    required this.nodes,
    required this.edges,
    this.maxDepth = 3,
    this.blastRadiusScope = 'local blast radius within 3 levels',
  });

  final String graphId;
  final String rootPackage;
  final String rootVersion;
  final List<GraphNodeData> nodes;
  final List<GraphEdgeData> edges;
  final int maxDepth;
  final String blastRadiusScope;

  factory DependencyGraphData.fromJson(Map<String, dynamic> json) {
    return DependencyGraphData(
      graphId: (json['graphId'] ?? json['graph_id'] ?? '') as String,
      rootPackage: (json['rootPackage'] ?? json['root_package'] ?? '') as String,
      rootVersion: (json['rootVersion'] ?? json['root_version'] ?? '') as String,
      nodes: (json['nodes'] as List<dynamic>? ?? [])
          .map((n) => GraphNodeData.fromJson(n as Map<String, dynamic>))
          .toList(),
      edges: (json['edges'] as List<dynamic>? ?? [])
          .map((e) => GraphEdgeData.fromJson(e as Map<String, dynamic>))
          .toList(),
      maxDepth: (json['maxDepth'] ?? json['max_depth'] ?? 3) as int,
      blastRadiusScope: (json['blastRadiusScope'] ?? json['blast_radius_scope'] ?? 'local blast radius within 3 levels') as String,
    );
  }
}

/// Alert item returned when a rescan detects risk changes or new CVEs
class RescanAlertData {
  const RescanAlertData({
    required this.packageName,
    required this.previousVersion,
    required this.newVersion,
    required this.previousRiskLevel,
    required this.previousRiskScore,
    required this.newRiskLevel,
    required this.newRiskScore,
    required this.versionChanged,
    required this.riskIncreased,
    this.knownVulnerabilities = const [],
  });

  final String packageName;
  final String previousVersion;
  final String newVersion;
  final String previousRiskLevel;
  final double previousRiskScore;
  final String newRiskLevel;
  final double newRiskScore;
  final bool versionChanged;
  final bool riskIncreased;
  final List<KnownVulnerability> knownVulnerabilities;

  factory RescanAlertData.fromJson(Map<String, dynamic> json) {
    return RescanAlertData(
      packageName: (json['packageName'] ?? json['package_name'] ?? '') as String,
      previousVersion: (json['previousVersion'] ?? json['previous_version'] ?? '') as String,
      newVersion: (json['newVersion'] ?? json['new_version'] ?? '') as String,
      previousRiskLevel: (json['previousRiskLevel'] ?? json['previous_risk_level'] ?? 'safe') as String,
      previousRiskScore: ((json['previousRiskScore'] ?? json['previous_risk_score'] ?? 0.0) as num).toDouble(),
      newRiskLevel: (json['newRiskLevel'] ?? json['new_risk_level'] ?? 'safe') as String,
      newRiskScore: ((json['newRiskScore'] ?? json['new_risk_score'] ?? 0.0) as num).toDouble(),
      versionChanged: (json['versionChanged'] ?? json['version_changed'] ?? false) as bool,
      riskIncreased: (json['riskIncreased'] ?? json['risk_increased'] ?? false) as bool,
      knownVulnerabilities: (json['knownVulnerabilities'] as List<dynamic>? ??
              json['known_vulnerabilities'] as List<dynamic>? ??
              [])
          .map((v) => KnownVulnerability.fromJson(v as Map<String, dynamic>))
          .toList(),
    );
  }

  Map<String, dynamic> toJson() => {
        'packageName': packageName,
        'previousVersion': previousVersion,
        'newVersion': newVersion,
        'previousRiskLevel': previousRiskLevel,
        'previousRiskScore': previousRiskScore,
        'newRiskLevel': newRiskLevel,
        'newRiskScore': newRiskScore,
        'versionChanged': versionChanged,
        'riskIncreased': riskIncreased,
        'knownVulnerabilities': knownVulnerabilities.map((v) => v.toJson()).toList(),
      };
}

/// Response payload from `/scan/rescan-check`
class RescanCheckResult {
  const RescanCheckResult({
    required this.checked,
    required this.changed,
    required this.alerts,
    required this.timestamp,
    required this.jobStatus,
  });

  final int checked;
  final int changed;
  final List<RescanAlertData> alerts;
  final String timestamp;
  final String jobStatus;

  factory RescanCheckResult.fromJson(Map<String, dynamic> json) {
    return RescanCheckResult(
      checked: (json['checked'] ?? 0) as int,
      changed: (json['changed'] ?? 0) as int,
      alerts: (json['alerts'] as List<dynamic>? ?? [])
          .map((a) => RescanAlertData.fromJson(a as Map<String, dynamic>))
          .toList(),
      timestamp: (json['timestamp'] ?? '') as String,
      jobStatus: (json['jobStatus'] ?? json['job_status'] ?? 'completed') as String,
    );
  }

  Map<String, dynamic> toJson() => {
        'checked': checked,
        'changed': changed,
        'alerts': alerts.map((a) => a.toJson()).toList(),
        'timestamp': timestamp,
        'jobStatus': jobStatus,
      };
}
