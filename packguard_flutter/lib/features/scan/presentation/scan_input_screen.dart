import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../core/theme/app_colors.dart';
import '../../../core/widgets/pg_button.dart';
import '../application/scan_providers.dart';
import 'widgets/package_autocomplete_field.dart';

class ScanInputScreen extends ConsumerWidget {
  const ScanInputScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final input = ref.watch(scanInputProvider);
    final notifier = ref.read(scanInputProvider.notifier);

    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(20, 16, 20, 24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('New scan', style: Theme.of(context).textTheme.headlineMedium),
            const SizedBox(height: 6),
            const Text(
              'Static analysis only — we never execute the package.',
              style: TextStyle(color: AppColors.textMuted),
            ),
            const SizedBox(height: 20),
            _ModeToggle(
              mode: input.mode,
              onChanged: notifier.setMode,
            ),
            const SizedBox(height: 20),
            Expanded(
              child: SingleChildScrollView(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    if (input.mode == ScanInputMode.package) ...[
                      PackageAutocompleteField(autofocus: true),
                      const SizedBox(height: 18),
                      const Text(
                        'Quick test packages (Viva demos):',
                        style: TextStyle(color: AppColors.textMuted, fontSize: 12),
                      ),
                      const SizedBox(height: 8),
                      Wrap(
                        spacing: 8,
                        runSpacing: 8,
                        children: [
                          _quickChip(context, ref, 'requests', isSafe: true),
                          _quickChip(context, ref, 'reqeusts', isSafe: false), // typosquat
                          _quickChip(context, ref, 'urllib3', isSafe: true),
                          _quickChip(context, ref, 'colorama', isSafe: true),
                        ],
                      ),
                    ] else
                      _RequirementsPicker(
                        fileName: input.fileName,
                        fileSize: input.fileSize,
                        onPick: () async {
                          final result = await FilePicker.platform.pickFiles(
                            type: FileType.custom,
                            allowedExtensions: ['txt'],
                            withData: true,
                          );
                          final file = result?.files.single;
                          if (file != null) {
                            notifier.setRequirementsFile(
                              path: file.path,
                              bytes: file.bytes,
                              filename: file.name,
                              size: file.size,
                            );
                          }
                        },
                        onRemove: notifier.clearFile,
                      ),
                  ],
                ),
              ),
            ),
            PgButton(
              label: 'Scan Now',
              onPressed: input.canScan ? () => context.push('/scan/progress') : null,
            ),
          ],
        ),
      ),
    );
  }

  Widget _quickChip(BuildContext context, WidgetRef ref, String name, {required bool isSafe}) {
    return ActionChip(
      label: Text(
        name,
        style: TextStyle(
          color: isSafe ? AppColors.accent : AppColors.suspicious,
          fontSize: 12,
          fontWeight: FontWeight.w600,
        ),
      ),
      backgroundColor: AppColors.surface,
      side: BorderSide(
        color: isSafe ? AppColors.accent.withOpacity( 0.4) : AppColors.suspicious.withOpacity( 0.4),
      ),
      onPressed: () {
        ref.read(scanInputProvider.notifier).pickSuggestion(name);
      },
    );
  }
}

class _ModeToggle extends StatelessWidget {
  const _ModeToggle({required this.mode, required this.onChanged});

  final ScanInputMode mode;
  final ValueChanged<ScanInputMode> onChanged;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(4),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.border),
      ),
      child: Row(
        children: [
          _chip('Search package', ScanInputMode.package),
          _chip('Upload requirements.txt', ScanInputMode.requirements),
        ],
      ),
    );
  }

  Widget _chip(String label, ScanInputMode value) {
    final selected = mode == value;
    return Expanded(
      child: GestureDetector(
        onTap: () => onChanged(value),
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 180),
          padding: const EdgeInsets.symmetric(vertical: 10),
          decoration: BoxDecoration(
            color: selected ? AppColors.surfaceElevated : Colors.transparent,
            borderRadius: BorderRadius.circular(10),
            border: selected ? Border.all(color: AppColors.accent.withOpacity( 0.4)) : null,
          ),
          child: Text(
            label,
            textAlign: TextAlign.center,
            style: TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.w600,
              color: selected ? AppColors.accent : AppColors.textSecondary,
            ),
          ),
        ),
      ),
    );
  }
}

class _RequirementsPicker extends StatelessWidget {
  const _RequirementsPicker({
    required this.fileName,
    this.fileSize,
    required this.onPick,
    required this.onRemove,
  });

  final String? fileName;
  final int? fileSize;
  final VoidCallback onPick;
  final VoidCallback onRemove;

  @override
  Widget build(BuildContext context) {
    if (fileName == null) {
      return GestureDetector(
        onTap: onPick,
        child: Container(
          width: double.infinity,
          padding: const EdgeInsets.symmetric(vertical: 36, horizontal: 20),
          decoration: BoxDecoration(
            color: AppColors.surface,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: AppColors.border, style: BorderStyle.solid),
          ),
          child: const Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(Icons.upload_file, color: AppColors.accent, size: 44),
              SizedBox(height: 12),
              Text(
                'Tap to pick requirements.txt',
                style: TextStyle(color: AppColors.textPrimary, fontWeight: FontWeight.w600),
              ),
              SizedBox(height: 4),
              Text(
                'Standard pip manifest (.txt only)',
                style: TextStyle(color: AppColors.textMuted, fontSize: 12),
              ),
            ],
          ),
        ),
      );
    }

    final sizeLabel = fileSize != null
        ? '${(fileSize! / 1024).toStringAsFixed(1)} KB'
        : 'File attached';

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppColors.accent.withOpacity( 0.5)),
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: AppColors.accent.withOpacity( 0.12),
              borderRadius: BorderRadius.circular(8),
            ),
            child: const Icon(Icons.description_outlined, color: AppColors.accent, size: 24),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  fileName!,
                  style: const TextStyle(
                    color: AppColors.textPrimary,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  sizeLabel,
                  style: const TextStyle(color: AppColors.textMuted, fontSize: 12),
                ),
              ],
            ),
          ),
          IconButton(
            onPressed: onRemove,
            icon: const Icon(Icons.delete_outline, color: AppColors.highRisk),
            tooltip: 'Remove file',
          ),
        ],
      ),
    );
  }
}
