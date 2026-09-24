import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../core/theme/app_colors.dart';
import '../../../core/widgets/risk_badge.dart';
import '../../../shared_models/risk_level.dart';
import '../../scan/application/scan_providers.dart';
import '../../scan/data/models/scan_models.dart';
import '../application/graph_providers.dart';

/// Dependency Graph Visualization Screen
///
/// VIVA ARCHITECTURE EXPLANATION:
/// 1. Algorithmic BFS Level Assignment: Parses directed edges from `/scan/dependency-graph`
///    and assigns topological hierarchy layers (Root -> Direct Deps -> Transitive Deps).
/// 2. Interactive Canvas: Utilizes [InteractiveViewer] with 2D transformations (pinch-to-zoom,
///    panning) and a [CustomPainter] that calculates Bezier curve connecting edges.
/// 3. Deep Dive Bottom Sheet: Tapping any node displays a modal risk summary and allows
///    immediate 1-tap single-package security scanning of that transitive dependency.
class DependencyGraphScreen extends ConsumerStatefulWidget {
  const DependencyGraphScreen({super.key, required this.packageName});

  final String packageName;

  @override
  ConsumerState<DependencyGraphScreen> createState() => _DependencyGraphScreenState();
}

class _DependencyGraphScreenState extends ConsumerState<DependencyGraphScreen> {
  final TransformationController _transformController = TransformationController();

  void _resetZoom() {
    _transformController.value = Matrix4.identity();
  }

  void _showNodeDetails(BuildContext context, GraphNodeData node) {
    final level = RiskLevel.fromApi(node.riskLevel);
    if (level == RiskLevel.highRisk) {
      HapticFeedback.heavyImpact();
    } else {
      HapticFeedback.selectionClick();
    }

    showModalBottomSheet<void>(
      context: context,
      backgroundColor: AppColors.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (context) {
        return SafeArea(
          child: Padding(
            padding: const EdgeInsets.fromLTRB(24, 16, 24, 24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Center(
                  child: Container(
                    width: 40,
                    height: 4,
                    decoration: BoxDecoration(
                      color: AppColors.border,
                      borderRadius: BorderRadius.circular(2),
                    ),
                  ),
                ),
                const SizedBox(height: 20),
                Row(
                  children: [
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            node.packageName,
                            style: const TextStyle(
                              fontSize: 20,
                              fontWeight: FontWeight.w700,
                              color: AppColors.textPrimary,
                            ),
                          ),
                          const SizedBox(height: 2),
                          Text(
                            'Version ${node.version}',
                            style: const TextStyle(color: AppColors.textMuted, fontSize: 13),
                          ),
                        ],
                      ),
                    ),
                    RiskBadge(level: level),
                  ],
                ),
                const SizedBox(height: 16),
                Container(
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: AppColors.background,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: AppColors.border),
                  ),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceAround,
                    children: [
                      _metricCol('RISK SCORE', node.riskScore.toStringAsFixed(1), _riskColor(node.riskLevel)),
                      Container(width: 1, height: 28, color: AppColors.border),
                      _metricCol('RISK LEVEL', level.label, _riskColor(node.riskLevel)),
                    ],
                  ),
                ),
                const SizedBox(height: 12),
                Container(
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: AppColors.background,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: AppColors.border),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          const Row(
                            children: [
                              Icon(Icons.hub_outlined, size: 14, color: AppColors.accent),
                              SizedBox(width: 6),
                              Text(
                                'CRITICALITY',
                                style: TextStyle(
                                  color: AppColors.textSecondary,
                                  fontSize: 11,
                                  fontWeight: FontWeight.w600,
                                  letterSpacing: 0.6,
                                ),
                              ),
                            ],
                          ),
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                            decoration: BoxDecoration(
                              color: AppColors.surface,
                              borderRadius: BorderRadius.circular(6),
                              border: Border.all(color: AppColors.border),
                            ),
                            child: Text(
                              node.criticalityLabel,
                              style: TextStyle(
                                color: node.inDegree >= 3
                                    ? AppColors.highRisk
                                    : (node.inDegree == 2 ? AppColors.suspicious : AppColors.safe),
                                fontSize: 11,
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 12),
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceAround,
                        children: [
                          _metricCol('IN-DEGREE', '${node.inDegree}', AppColors.textPrimary),
                          Container(width: 1, height: 24, color: AppColors.border),
                          _metricCol('CENTRALITY', node.degreeCentrality.toStringAsFixed(3), AppColors.textPrimary),
                          Container(width: 1, height: 24, color: AppColors.border),
                          _metricCol('TREE DEPTH', 'Level ${node.depthInTree}', AppColors.accent),
                        ],
                      ),
                      const SizedBox(height: 8),
                      Text(
                        'Note: ${node.blastRadiusScope}',
                        style: const TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 10,
                          fontStyle: FontStyle.italic,
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 18),
                SizedBox(
                  width: double.infinity,
                  height: 48,
                  child: ElevatedButton.icon(
                    onPressed: () {
                      Navigator.pop(context);
                      ref.read(scanInputProvider.notifier).pickSuggestion(node.packageName);
                      context.push('/scan/progress');
                    },
                    icon: const Icon(Icons.radar, size: 18),
                    label: Text('Deep Scan "${node.packageName}"'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: AppColors.accent,
                      foregroundColor: AppColors.background,
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                    ),
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  Color _criticalityColor(GraphNodeData node) {
    if (node.inDegree >= 3) return AppColors.highRisk;
    if (node.inDegree == 2) return AppColors.suspicious;
    return AppColors.safe;
  }

  Color _criticalityBadgeBg(GraphNodeData node) {
    return _criticalityColor(node).withOpacity(0.14);
  }

  Widget _metricCol(String label, String value, Color color) {
    return Column(
      children: [
        Text(label, style: const TextStyle(color: AppColors.textMuted, fontSize: 10, letterSpacing: 0.8)),
        const SizedBox(height: 4),
        Text(value, style: TextStyle(color: color, fontWeight: FontWeight.w700, fontSize: 16)),
      ],
    );
  }

  Color _riskColor(String level) {
    switch (level.toLowerCase()) {
      case 'safe':
        return AppColors.safe;
      case 'suspicious':
        return AppColors.suspicious;
      case 'high_risk':
        return AppColors.highRisk;
      default:
        return AppColors.textMuted;
    }
  }

  @override
  Widget build(BuildContext context) {
    final graphAsync = ref.watch(dependencyGraphProvider(widget.packageName));

    return Scaffold(
      appBar: AppBar(
        title: Text('Graph: ${widget.packageName}'),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => context.pop(),
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.center_focus_strong_outlined),
            tooltip: 'Reset Zoom',
            onPressed: _resetZoom,
          ),
        ],
      ),
      body: graphAsync.when(
        loading: () => const Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              CircularProgressIndicator(color: AppColors.accent),
              SizedBox(height: 16),
              Text(
                'Resolving recursive dependencies…',
                style: TextStyle(color: AppColors.textMuted),
              ),
            ],
          ),
        ),
        error: (err, _) => Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.error_outline, size: 40, color: AppColors.highRisk),
                const SizedBox(height: 12),
                Text(
                  'Failed to build dependency tree: $err',
                  textAlign: TextAlign.center,
                  style: const TextStyle(color: AppColors.textSecondary),
                ),
                const SizedBox(height: 16),
                OutlinedButton(
                  onPressed: () => ref.invalidate(dependencyGraphProvider(widget.packageName)),
                  child: const Text('Retry'),
                ),
              ],
            ),
          ),
        ),
        data: (graphData) {
          if (graphData.nodes.isEmpty) {
            return const Center(
              child: Text('No dependencies found for this package.', style: TextStyle(color: AppColors.textMuted)),
            );
          }

          // Build node coordinate mapping using topological BFS layers
          final layout = _computeLayout(graphData);

          return Stack(
            children: [
              InteractiveViewer(
                transformationController: _transformController,
                boundaryMargin: const EdgeInsets.all(800),
                minScale: 0.3,
                maxScale: 3.5,
                constrained: false,
                child: SizedBox(
                  width: layout.width,
                  height: layout.height,
                  child: Stack(
                    children: [
                      // Edges connecting nodes
                      CustomPaint(
                        size: Size(layout.width, layout.height),
                        painter: _GraphEdgePainter(
                          edges: graphData.edges,
                          nodePositions: layout.positions,
                        ),
                      ),
                      // Interactive node cards
                      ...graphData.nodes.map((node) {
                        final pos = layout.positions[node.id] ?? Offset.zero;
                        final isRoot = node.packageName.toLowerCase() == graphData.rootPackage.toLowerCase();
                        final color = _riskColor(node.riskLevel);

                        return Positioned(
                          left: pos.dx - 110,
                          top: pos.dy - 43,
                          child: GestureDetector(
                            onTap: () => _showNodeDetails(context, node),
                            child: Container(
                              width: 220,
                              height: 86,
                              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                              decoration: BoxDecoration(
                                color: AppColors.surface,
                                borderRadius: BorderRadius.circular(12),
                                border: Border.all(
                                  color: isRoot ? AppColors.accent : color,
                                  width: isRoot ? 2.2 : 1.4,
                                ),
                                boxShadow: [
                                  BoxShadow(
                                    color: (isRoot ? AppColors.accent : color).withOpacity(0.2),
                                    blurRadius: 10,
                                  ),
                                ],
                              ),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                                children: [
                                  Row(
                                    children: [
                                      Container(
                                        width: 8,
                                        height: 8,
                                        decoration: BoxDecoration(
                                          shape: BoxShape.circle,
                                          color: color,
                                        ),
                                      ),
                                      const SizedBox(width: 6),
                                      Expanded(
                                        child: Text(
                                          node.packageName,
                                          maxLines: 1,
                                          overflow: TextOverflow.ellipsis,
                                          style: const TextStyle(
                                            color: AppColors.textPrimary,
                                            fontWeight: FontWeight.w700,
                                            fontSize: 12,
                                          ),
                                        ),
                                      ),
                                      if (isRoot) ...[
                                        const SizedBox(width: 4),
                                        Container(
                                          padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1.5),
                                          decoration: BoxDecoration(
                                            color: AppColors.accent.withOpacity(0.18),
                                            borderRadius: BorderRadius.circular(4),
                                            border: Border.all(color: AppColors.accent.withOpacity(0.4), width: 0.8),
                                          ),
                                          child: const Text(
                                            'ROOT',
                                            style: TextStyle(
                                              color: AppColors.accent,
                                              fontSize: 9,
                                              fontWeight: FontWeight.w700,
                                              letterSpacing: 0.4,
                                            ),
                                          ),
                                        ),
                                      ],
                                    ],
                                  ),
                                  Container(
                                    width: double.infinity,
                                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2.5),
                                    decoration: BoxDecoration(
                                      color: _criticalityBadgeBg(node),
                                      borderRadius: BorderRadius.circular(5),
                                      border: Border.all(
                                        color: _criticalityColor(node).withOpacity(0.35),
                                        width: 0.8,
                                      ),
                                    ),
                                    child: Row(
                                      mainAxisSize: MainAxisSize.min,
                                      children: [
                                        Icon(Icons.hub_outlined, size: 10, color: _criticalityColor(node)),
                                        const SizedBox(width: 4),
                                        Expanded(
                                          child: Text(
                                            'Criticality: ${node.criticalityLabel}',
                                            maxLines: 1,
                                            overflow: TextOverflow.ellipsis,
                                            style: TextStyle(
                                              color: _criticalityColor(node),
                                              fontSize: 9.5,
                                              fontWeight: FontWeight.w700,
                                            ),
                                          ),
                                        ),
                                      ],
                                    ),
                                  ),
                                  Text(
                                    'v${node.version} · L${node.depthInTree} · score ${node.riskScore.toInt()}',
                                    style: const TextStyle(
                                      color: AppColors.textMuted,
                                      fontSize: 9.5,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        );
                      }),
                    ],
                  ),
                ),
              ),

              // Legend Overlay
              Positioned(
                bottom: 20,
                left: 20,
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                  decoration: BoxDecoration(
                    color: AppColors.surface.withOpacity( 0.92),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: AppColors.border),
                  ),
                  child: Row(
                    children: [
                      _legendDot(AppColors.safe, 'Safe'),
                      const SizedBox(width: 12),
                      _legendDot(AppColors.suspicious, 'Suspicious'),
                      const SizedBox(width: 12),
                      _legendDot(AppColors.highRisk, 'High Risk'),
                      const SizedBox(width: 12),
                      Container(width: 1, height: 14, color: AppColors.border),
                      const SizedBox(width: 12),
                      const Icon(Icons.info_outline, size: 12, color: AppColors.textMuted),
                      const SizedBox(width: 4),
                      const Text(
                        'Blast radius \u2264 3 levels',
                        style: TextStyle(color: AppColors.textMuted, fontSize: 10),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          );
        },
      ),
    );
  }

  Widget _legendDot(Color color, String label) {
    return Row(
      children: [
        Container(width: 8, height: 8, decoration: BoxDecoration(color: color, shape: BoxShape.circle)),
        const SizedBox(width: 5),
        Text(label, style: const TextStyle(color: AppColors.textSecondary, fontSize: 11)),
      ],
    );
  }

  _GraphLayout _computeLayout(DependencyGraphData graph) {
    final Map<String, int> depths = {};
    final rootId = graph.nodes.firstWhere(
      (n) => n.packageName.toLowerCase() == graph.rootPackage.toLowerCase(),
      orElse: () => graph.nodes.first,
    ).id;

    // Breadth-First-Search from root to calculate levels
    depths[rootId] = 0;
    final Map<String, List<String>> adj = {};
    for (final e in graph.edges) {
      adj.putIfAbsent(e.source, () => []).add(e.target);
    }

    final queue = [rootId];
    while (queue.isNotEmpty) {
      final cur = queue.removeAt(0);
      final d = depths[cur] ?? 0;
      for (final next in adj[cur] ?? <String>[]) {
        if (!depths.containsKey(next)) {
          depths[next] = d + 1;
          queue.add(next);
        }
      }
    }

    // Default remaining unlinked nodes to depth 1
    for (final n in graph.nodes) {
      depths.putIfAbsent(n.id, () => 1);
    }

    // Group nodes by depth
    final Map<int, List<String>> levels = {};
    for (final entry in depths.entries) {
      levels.putIfAbsent(entry.value, () => []).add(entry.key);
    }

    const double levelGap = 175.0;
    const double nodeGap = 250.0;

    int maxNodesInLevel = 1;
    for (final list in levels.values) {
      if (list.length > maxNodesInLevel) maxNodesInLevel = list.length;
    }

    final canvasWidth = math.max(1200.0, maxNodesInLevel * nodeGap + 300);
    final canvasHeight = math.max(800.0, (levels.length + 1) * levelGap + 200);

    final Map<String, Offset> positions = {};
    for (final entry in levels.entries) {
      final level = entry.key;
      final nodesInLevel = entry.value;
      final y = 100.0 + level * levelGap;
      final totalWidth = nodesInLevel.length * nodeGap;
      final startX = (canvasWidth - totalWidth) / 2 + nodeGap / 2;

      for (var i = 0; i < nodesInLevel.length; i++) {
        positions[nodesInLevel[i]] = Offset(startX + i * nodeGap, y);
      }
    }

    return _GraphLayout(
      width: canvasWidth,
      height: canvasHeight,
      positions: positions,
    );
  }
}

class _GraphLayout {
  const _GraphLayout({required this.width, required this.height, required this.positions});
  final double width;
  final double height;
  final Map<String, Offset> positions;
}

/// Custom edge painter drawing directed curves with arrowheads
class _GraphEdgePainter extends CustomPainter {
  _GraphEdgePainter({required this.edges, required this.nodePositions});

  final List<GraphEdgeData> edges;
  final Map<String, Offset> nodePositions;

  @override
  void paint(Canvas canvas, Size size) {
    final edgePaint = Paint()
      ..color = AppColors.border
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1.6;

    final arrowPaint = Paint()
      ..color = AppColors.textMuted
      ..style = PaintingStyle.fill;

    for (final edge in edges) {
      final from = nodePositions[edge.source];
      final to = nodePositions[edge.target];
      if (from == null || to == null) continue;

      final start = Offset(from.dx, from.dy + 43);
      final end = Offset(to.dx, to.dy - 43);

      final path = Path();
      path.moveTo(start.dx, start.dy);
      final midY = (start.dy + end.dy) / 2;
      path.cubicTo(start.dx, midY, end.dx, midY, end.dx, end.dy);
      canvas.drawPath(path, edgePaint);

      // Draw arrowhead at end
      final arrowPath = Path();
      arrowPath.moveTo(end.dx, end.dy);
      arrowPath.lineTo(end.dx - 4, end.dy - 8);
      arrowPath.lineTo(end.dx + 4, end.dy - 8);
      arrowPath.close();
      canvas.drawPath(arrowPath, arrowPaint);
    }
  }

  @override
  bool shouldRepaint(covariant _GraphEdgePainter oldDelegate) => true;
}
