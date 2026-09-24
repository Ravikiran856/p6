import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/theme/app_colors.dart';
import '../../../scan/application/scan_providers.dart';

/// Debounced autocomplete. The debounce lives in [ScanInputNotifier] so Dashboard
/// and Scan Input share one search pipeline.
class PackageAutocompleteField extends ConsumerStatefulWidget {
  const PackageAutocompleteField({
    super.key,
    this.autofocus = false,
    this.onSubmitted,
  });

  final bool autofocus;
  final ValueChanged<String>? onSubmitted;

  @override
  ConsumerState<PackageAutocompleteField> createState() =>
      _PackageAutocompleteFieldState();
}

class _PackageAutocompleteFieldState extends ConsumerState<PackageAutocompleteField> {
  late final TextEditingController _controller;
  bool _syncing = false;

  @override
  void initState() {
    super.initState();
    _controller = TextEditingController(text: ref.read(scanInputProvider).packageName);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final input = ref.watch(scanInputProvider);
    if (!_syncing && _controller.text != input.packageName) {
      _controller.value = TextEditingValue(
        text: input.packageName,
        selection: TextSelection.collapsed(offset: input.packageName.length),
      );
    }

    return Column(
      children: [
        TextField(
          controller: _controller,
          autofocus: widget.autofocus,
          onChanged: (v) {
            _syncing = true;
            ref.read(scanInputProvider.notifier).setPackageName(v);
            _syncing = false;
          },
          onSubmitted: (v) {
            if (v.trim().length >= 2) widget.onSubmitted?.call(v.trim());
          },
          style: const TextStyle(color: AppColors.textPrimary),
          decoration: InputDecoration(
            hintText: 'Search a PyPI package…',
            prefixIcon: const Icon(Icons.search, color: AppColors.textMuted),
            suffixIcon: _controller.text.isNotEmpty
                ? IconButton(
                    icon: const Icon(Icons.clear, size: 18, color: AppColors.textMuted),
                    onPressed: () {
                      _controller.clear();
                      ref.read(scanInputProvider.notifier).setPackageName('');
                    },
                  )
                : null,
          ),
        ),
        if (input.searching)
          const Padding(
            padding: EdgeInsets.only(top: 8),
            child: LinearProgressIndicator(
              minHeight: 2,
              color: AppColors.accent,
              backgroundColor: AppColors.surface,
            ),
          ),
        if (input.suggestions.isNotEmpty)
          Container(
            margin: const EdgeInsets.only(top: 6),
            decoration: BoxDecoration(
              color: AppColors.surface,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: AppColors.border),
            ),
            constraints: const BoxConstraints(maxHeight: 220),
            child: ListView(
              shrinkWrap: true,
              physics: const ClampingScrollPhysics(),
              children: input.suggestions.map((s) {
                return ListTile(
                  dense: true,
                  title: Text(s.name, style: const TextStyle(color: AppColors.textPrimary)),
                  subtitle: Text(
                    s.isKnownTop5000 ? 'Top 5000 PyPI package' : 'Unranked / New package',
                    style: TextStyle(
                      fontSize: 11,
                      color: s.isKnownTop5000 ? AppColors.safe : AppColors.suspicious,
                    ),
                  ),
                  trailing: const Icon(Icons.north_west, size: 14, color: AppColors.textMuted),
                  onTap: () {
                    FocusScope.of(context).unfocus();
                    ref.read(scanInputProvider.notifier).pickSuggestion(s.name);
                    widget.onSubmitted?.call(s.name);
                  },
                );
              }).toList(),
            ),
          ),
      ],
    );
  }
}
