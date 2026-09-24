import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../core/theme/app_colors.dart';
import '../../../core/widgets/pg_button.dart';
import '../../../core/widgets/pg_text_field.dart';
import '../application/auth_providers.dart';

class SignupScreen extends ConsumerStatefulWidget {
  const SignupScreen({super.key});

  @override
  ConsumerState<SignupScreen> createState() => _SignupScreenState();
}

class _SignupScreenState extends ConsumerState<SignupScreen> {
  final _email = TextEditingController();
  final _password = TextEditingController();
  final _confirm = TextEditingController();

  bool get _canSubmit =>
      _email.text.trim().isNotEmpty &&
      _email.text.contains('@') &&
      _password.text.length >= 6 &&
      _password.text == _confirm.text;

  @override
  void dispose() {
    _email.dispose();
    _password.dispose();
    _confirm.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (!_canSubmit) return;
    final ok = await ref
        .read(authControllerProvider.notifier)
        .signUp(_email.text, _password.text);
    if (ok && mounted) context.go('/dashboard');
  }

  @override
  Widget build(BuildContext context) {
    final auth = ref.watch(authControllerProvider);
    final loading = auth.isLoading;
    final error = auth.hasError ? auth.error.toString() : null;

    final passwordsMatch = _confirm.text.isEmpty || _password.text == _confirm.text;

    return Scaffold(
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 32),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              IconButton(
                onPressed: () {
                  ref.read(authControllerProvider.notifier).clearError();
                  context.go('/login');
                },
                icon: const Icon(Icons.arrow_back),
              ),
              const SizedBox(height: 8),
              Text('Create account', style: Theme.of(context).textTheme.displayLarge?.copyWith(fontSize: 28)),
              const SizedBox(height: 8),
              const Text(
                'Creates your security analyst identity. PackGuard stores audit logs per-UID.',
                style: TextStyle(color: AppColors.textSecondary),
              ),
              const SizedBox(height: 28),
              PgTextField(
                controller: _email,
                label: 'Email',
                keyboardType: TextInputType.emailAddress,
                prefixIcon: Icons.mail_outline,
                onChanged: (_) => setState(() {}),
              ),
              const SizedBox(height: 14),
              PgTextField(
                controller: _password,
                label: 'Password (min. 6 chars)',
                obscure: true,
                prefixIcon: Icons.lock_outline,
                onChanged: (_) => setState(() {}),
              ),
              const SizedBox(height: 14),
              PgTextField(
                controller: _confirm,
                label: 'Confirm password',
                obscure: true,
                prefixIcon: Icons.lock_outline,
                onChanged: (_) => setState(() {}),
              ),
              if (!passwordsMatch) ...[
                const SizedBox(height: 6),
                const Text(
                  'Passwords do not match',
                  style: TextStyle(color: AppColors.highRisk, fontSize: 12),
                ),
              ],
              if (error != null) ...[
                const SizedBox(height: 14),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                  decoration: BoxDecoration(
                    color: AppColors.highRisk.withOpacity( 0.12),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: AppColors.highRisk.withOpacity( 0.45)),
                  ),
                  child: Row(
                    children: [
                      const Icon(Icons.error_outline, color: AppColors.highRisk, size: 18),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          error,
                          style: const TextStyle(color: AppColors.highRisk, fontSize: 13),
                        ),
                      ),
                      IconButton(
                        padding: EdgeInsets.zero,
                        constraints: const BoxConstraints(),
                        icon: const Icon(Icons.close, size: 16, color: AppColors.highRisk),
                        onPressed: () => ref.read(authControllerProvider.notifier).clearError(),
                      ),
                    ],
                  ),
                ),
              ],
              const SizedBox(height: 24),
              PgButton(
                label: 'Sign up',
                loading: loading,
                onPressed: (_canSubmit && !loading) ? _submit : null,
              ),
              const SizedBox(height: 20),
              Center(
                child: GestureDetector(
                  onTap: () {
                    ref.read(authControllerProvider.notifier).clearError();
                    context.go('/login');
                  },
                  child: const Text(
                    'Already have an account? Sign in',
                    style: TextStyle(color: AppColors.accent, fontWeight: FontWeight.w600),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
