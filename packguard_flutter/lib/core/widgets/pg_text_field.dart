import 'package:flutter/material.dart';

import '../theme/app_colors.dart';

/// Dark text field with a subtle scale/border focus animation.
class PgTextField extends StatefulWidget {
  const PgTextField({
    super.key,
    required this.controller,
    this.hint,
    this.label,
    this.obscure = false,
    this.keyboardType,
    this.prefixIcon,
    this.onChanged,
    this.textInputAction,
  });

  final TextEditingController controller;
  final String? hint;
  final String? label;
  final bool obscure;
  final TextInputType? keyboardType;
  final IconData? prefixIcon;
  final ValueChanged<String>? onChanged;
  final TextInputAction? textInputAction;

  @override
  State<PgTextField> createState() => _PgTextFieldState();
}

class _PgTextFieldState extends State<PgTextField> {
  late final FocusNode _focus = FocusNode();
  bool _focused = false;
  bool _hide = true;

  @override
  void initState() {
    super.initState();
    _hide = widget.obscure;
    _focus.addListener(() => setState(() => _focused = _focus.hasFocus));
  }

  @override
  void dispose() {
    _focus.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedScale(
      scale: _focused ? 1.01 : 1.0,
      duration: const Duration(milliseconds: 180),
      curve: Curves.easeOut,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 180),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(12),
          boxShadow: _focused
              ? [
                  BoxShadow(
                    color: AppColors.accent.withOpacity( 0.18),
                    blurRadius: 16,
                  ),
                ]
              : [],
        ),
        child: TextField(
          controller: widget.controller,
          focusNode: _focus,
          obscureText: widget.obscure && _hide,
          keyboardType: widget.keyboardType,
          textInputAction: widget.textInputAction,
          onChanged: widget.onChanged,
          style: const TextStyle(color: AppColors.textPrimary),
          decoration: InputDecoration(
            labelText: widget.label,
            hintText: widget.hint,
            prefixIcon: widget.prefixIcon == null
                ? null
                : Icon(widget.prefixIcon, color: AppColors.textSecondary),
            suffixIcon: widget.obscure
                ? IconButton(
                    icon: Icon(
                      _hide ? Icons.visibility_outlined : Icons.visibility_off_outlined,
                      color: AppColors.textMuted,
                    ),
                    onPressed: () => setState(() => _hide = !_hide),
                  )
                : null,
          ),
        ),
      ),
    );
  }
}
