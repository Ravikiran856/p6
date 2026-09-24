import 'package:flutter/material.dart';

import '../../../../core/theme/app_colors.dart';
import '../../../scan/data/models/scan_models.dart';

/// Expandable security finding card mapping explanation strings to categorized icons.
class ExpandableReasonCard extends StatefulWidget {
  const ExpandableReasonCard({
    super.key,
    required this.reason,
    required this.index,
  });

  final String reason;
  final int index;

  @override
  State<ExpandableReasonCard> createState() => _ExpandableReasonCardState();
}

class _ExpandableReasonCardState extends State<ExpandableReasonCard> {
  bool _expanded = false;

  _FindingCategory _detectCategory(String text) {
    final lower = text.toLowerCase();
    if (lower.contains('network') ||
        lower.contains('socket') ||
        lower.contains('urllib') ||
        lower.contains('http') ||
        lower.contains('connect') ||
        lower.contains('download')) {
      return const _FindingCategory(
        title: 'Network & Exfiltration',
        icon: Icons.wifi_tethering,
        color: AppColors.suspicious,
        recommendation: 'Inspect outbound IP destinations and ensure package does not leak environmental secrets.',
      );
    }
    if (lower.contains('eval') ||
        lower.contains('exec') ||
        lower.contains('subprocess') ||
        lower.contains('system(') ||
        lower.contains('popen') ||
        lower.contains('command')) {
      return const _FindingCategory(
        title: 'Dynamic Code / Subprocess Execution',
        icon: Icons.terminal,
        color: AppColors.highRisk,
        recommendation: 'Dynamic evaluation allows remote code execution (RCE). Audit any untrusted strings passed to shell.',
      );
    }
    if (lower.contains('file') ||
        lower.contains('open(') ||
        lower.contains('read') ||
        lower.contains('write') ||
        lower.contains('path') ||
        lower.contains('unlink')) {
      return const _FindingCategory(
        title: 'File System Access',
        icon: Icons.folder_open,
        color: AppColors.suspicious,
        recommendation: 'Verify package only reads declared resources and does not alter system configuration or ssh keys.',
      );
    }
    if (lower.contains('typo') ||
        lower.contains('squat') ||
        lower.contains('mimic') ||
        lower.contains('levenshtein') ||
        lower.contains('similar')) {
      return const _FindingCategory(
        title: 'Typosquatting Hazard',
        icon: Icons.spellcheck,
        color: AppColors.highRisk,
        recommendation: 'Name is deceptively close to an established popular package. Confirm exact package spelling with repository.',
      );
    }
    if (lower.contains('base64') ||
        lower.contains('obfuscate') ||
        lower.contains('decode') ||
        lower.contains('zlib') ||
        lower.contains('marshal')) {
      return const _FindingCategory(
        title: 'Payload Obfuscation',
        icon: Icons.enhanced_encryption,
        color: AppColors.highRisk,
        recommendation: 'Obfuscated or encrypted blobs in setup.py or package modules strongly correlate with malware droppers.',
      );
    }
    if (lower.contains('token') ||
        lower.contains('password') ||
        lower.contains('secret') ||
        lower.contains('env') ||
        lower.contains('credential')) {
      return const _FindingCategory(
        title: 'Credential Harvesting',
        icon: Icons.vpn_key,
        color: AppColors.highRisk,
        recommendation: 'Code reads sensitive environmental parameters or browser cookies without clear functional reason.',
      );
    }
    return const _FindingCategory(
      title: 'Suspicious Heuristic Flag',
      icon: Icons.warning_amber_rounded,
      color: AppColors.suspicious,
      recommendation: 'Static analysis flagged an uncommon pattern requiring manual peer review.',
    );
  }

  @override
  Widget build(BuildContext context) {
    final cat = _detectCategory(widget.reason);

    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(
          color: _expanded ? cat.color.withOpacity(0.6) : AppColors.border,
          width: _expanded ? 1.5 : 1.0,
        ),
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(14),
          onTap: () => setState(() => _expanded = !_expanded),
          child: Padding(
            padding: const EdgeInsets.all(14),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Container(
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: cat.color.withOpacity(0.12),
                        borderRadius: BorderRadius.circular(10),
                      ),
                      child: Icon(cat.icon, color: cat.color, size: 20),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Text(
                                cat.title,
                                style: TextStyle(
                                  fontSize: 12,
                                  fontWeight: FontWeight.w700,
                                  color: cat.color,
                                  letterSpacing: 0.4,
                                ),
                              ),
                              const Spacer(),
                              Icon(
                                _expanded ? Icons.keyboard_arrow_up : Icons.keyboard_arrow_down,
                                color: AppColors.textMuted,
                                size: 18,
                              ),
                            ],
                          ),
                          const SizedBox(height: 4),
                          Text(
                            widget.reason,
                            style: const TextStyle(
                              color: AppColors.textPrimary,
                              fontSize: 14,
                              fontWeight: FontWeight.w500,
                              height: 1.35,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
                if (_expanded) ...[
                  const SizedBox(height: 12),
                  const Divider(color: AppColors.border, height: 1),
                  const SizedBox(height: 10),
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Icon(Icons.shield_outlined, color: AppColors.accent, size: 16),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'Recommendation: ${cat.recommendation}',
                          style: const TextStyle(
                            fontSize: 12,
                            color: AppColors.textSecondary,
                            height: 1.3,
                          ),
                        ),
                      ),
                    ],
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// Rich structured security finding card rendering line numbers, file paths,
/// code snippets, and 7-category taxonomy badges.
///
/// Example display:
/// "Line 47 in setup.py — Reverse Shell pattern"
class ExpandableFindingCard extends StatefulWidget {
  const ExpandableFindingCard({
    super.key,
    required this.finding,
    required this.index,
  });

  final ScanFinding finding;
  final int index;

  @override
  State<ExpandableFindingCard> createState() => _ExpandableFindingCardState();
}

class _ExpandableFindingCardState extends State<ExpandableFindingCard> {
  bool _expanded = false;

  _FindingCategory _categoryDetails(String category) {
    switch (category) {
      case 'Execution':
        return const _FindingCategory(
          title: 'Execution',
          icon: Icons.terminal,
          color: AppColors.highRisk,
          recommendation: 'Subprocess or dynamic evaluation execution detected. Review code for remote command execution vulnerability.',
        );
      case 'Persistence':
        return const _FindingCategory(
          title: 'Persistence (Install Hook)',
          icon: Icons.extension,
          color: AppColors.highRisk,
          recommendation: 'Code runs during package installation (setup.py/cmdclass hook). Strongly correlated with supply chain droppers.',
        );
      case 'Defense Evasion':
        return const _FindingCategory(
          title: 'Defense Evasion',
          icon: Icons.enhanced_encryption,
          color: AppColors.highRisk,
          recommendation: 'Obfuscated strings, base64 payloads, or dynamic imports hide runtime behavior from scanners.',
        );
      case 'Exfiltration':
        return const _FindingCategory(
          title: 'Exfiltration',
          icon: Icons.wifi_tethering,
          color: AppColors.suspicious,
          recommendation: 'Outbound HTTP communication or data transmission. Confirm destinations are verified and authorized.',
        );
      case 'Discovery':
        return const _FindingCategory(
          title: 'Discovery',
          icon: Icons.search,
          color: AppColors.suspicious,
          recommendation: 'Code queries environment variables or sensitive files (.env, .aws, .ssh) for potential credential harvesting.',
        );
      case 'Command & Control':
        return const _FindingCategory(
          title: 'Command & Control',
          icon: Icons.hub_outlined,
          color: AppColors.highRisk,
          recommendation: 'Direct raw socket connection or external command & control URL referenced.',
        );
      case 'Metadata Manipulation':
        return const _FindingCategory(
          title: 'Metadata Manipulation',
          icon: Icons.spellcheck,
          color: AppColors.suspicious,
          recommendation: 'Deceptive typosquatting similarity, unverified dependency, or abnormal release bursts.',
        );
      default:
        return const _FindingCategory(
          title: 'Security Finding',
          icon: Icons.security,
          color: AppColors.suspicious,
          recommendation: 'Static analysis pattern flagged for manual review.',
        );
    }
  }

  @override
  Widget build(BuildContext context) {
    final cat = _categoryDetails(widget.finding.category);
    final isInstall = widget.finding.filePath.toLowerCase().endsWith('setup.py') ||
        widget.finding.filePath.toLowerCase().endsWith('__init__.py') ||
        widget.finding.category == 'Persistence';

    final title = widget.finding.title ?? widget.finding.indicatorId;
    final headerText = 'Line ${widget.finding.lineNumber} in ${widget.finding.filePath} — $title';

    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(
          color: _expanded ? cat.color.withOpacity(0.6) : AppColors.border,
          width: _expanded ? 1.5 : 1.0,
        ),
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(14),
          onTap: () => setState(() => _expanded = !_expanded),
          child: Padding(
            padding: const EdgeInsets.all(14),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Container(
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: cat.color.withOpacity(0.12),
                        borderRadius: BorderRadius.circular(10),
                      ),
                      child: Icon(cat.icon, color: cat.color, size: 20),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                decoration: BoxDecoration(
                                  color: cat.color.withOpacity(0.15),
                                  borderRadius: BorderRadius.circular(4),
                                ),
                                child: Text(
                                  cat.title.toUpperCase(),
                                  style: TextStyle(
                                    fontSize: 10,
                                    fontWeight: FontWeight.w800,
                                    color: cat.color,
                                    letterSpacing: 0.5,
                                  ),
                                ),
                              ),
                              if (isInstall) ...[
                                const SizedBox(width: 6),
                                Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                                  decoration: BoxDecoration(
                                    color: AppColors.highRisk.withOpacity(0.2),
                                    borderRadius: BorderRadius.circular(4),
                                    border: Border.all(color: AppColors.highRisk.withOpacity(0.4)),
                                  ),
                                  child: const Text(
                                    '1.5x WEIGHT',
                                    style: TextStyle(
                                      fontSize: 9,
                                      fontWeight: FontWeight.w700,
                                      color: AppColors.highRisk,
                                    ),
                                  ),
                                ),
                              ],
                              const Spacer(),
                              Icon(
                                _expanded ? Icons.keyboard_arrow_up : Icons.keyboard_arrow_down,
                                color: AppColors.textMuted,
                                size: 18,
                              ),
                            ],
                          ),
                          const SizedBox(height: 6),
                          Text(
                            headerText,
                            style: const TextStyle(
                              color: AppColors.textPrimary,
                              fontSize: 13.5,
                              fontWeight: FontWeight.w600,
                              height: 1.35,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
                if (_expanded) ...[
                  const SizedBox(height: 12),
                  const Divider(color: AppColors.border, height: 1),
                  const SizedBox(height: 10),

                  // Code snippet section
                  if (widget.finding.codeSnippet.isNotEmpty) ...[
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                      decoration: BoxDecoration(
                        color: AppColors.background,
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: AppColors.border),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Text(
                                '${widget.finding.filePath}:${widget.finding.lineNumber}',
                                style: const TextStyle(
                                  color: AppColors.textMuted,
                                  fontSize: 10,
                                  fontFamily: 'monospace',
                                ),
                              ),
                              const Spacer(),
                              Text(
                                widget.finding.indicatorId,
                                style: const TextStyle(
                                  color: AppColors.textMuted,
                                  fontSize: 10,
                                  fontFamily: 'monospace',
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 4),
                          Text(
                            widget.finding.codeSnippet,
                            style: const TextStyle(
                              fontFamily: 'monospace',
                              fontSize: 12,
                              color: AppColors.accent,
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 10),
                  ],

                  // Recommendation
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Icon(Icons.shield_outlined, color: AppColors.accent, size: 16),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'Recommendation: ${cat.recommendation}',
                          style: const TextStyle(
                            fontSize: 12,
                            color: AppColors.textSecondary,
                            height: 1.3,
                          ),
                        ),
                      ),
                    ],
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _FindingCategory {
  const _FindingCategory({
    required this.title,
    required this.icon,
    required this.color,
    required this.recommendation,
  });

  final String title;
  final IconData icon;
  final Color color;
  final String recommendation;
}
