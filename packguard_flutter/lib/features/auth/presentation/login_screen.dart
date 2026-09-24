import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../core/constants/app_constants.dart';
import '../../../core/theme/app_colors.dart';
import '../../../core/widgets/pg_button.dart';
import '../../../core/widgets/pg_text_field.dart';
import '../application/auth_providers.dart';

class LoginScreen extends ConsumerStatefulWidget {
  const LoginScreen({super.key});

  @override
  ConsumerState<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends ConsumerState<LoginScreen> {
  final _email = TextEditingController();
  final _password = TextEditingController();

  bool get _canSubmit =>
      _email.text.trim().isNotEmpty &&
      _email.text.contains('@') &&
      _password.text.isNotEmpty;

  @override
  void dispose() {
    _email.dispose();
    _password.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (!_canSubmit) return;
    final ok = await ref
        .read(authControllerProvider.notifier)
        .signIn(_email.text, _password.text);
    if (ok && mounted) context.go('/dashboard');
  }

  Future<void> _demoLogin() async {
    final ok = await ref
        .read(authControllerProvider.notifier)
        .signInDemo('analyst@packguard.dev');
    if (ok && mounted) context.go('/dashboard');
  }

  @override
  Widget build(BuildContext context) {
    final auth = ref.watch(authControllerProvider);
    final loading = auth.isLoading;
    final error = auth.hasError ? auth.error.toString() : null;
    final demo = ref.watch(authRepositoryProvider).demoMode;

    return Scaffold(
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 32),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SizedBox(height: 16),
              // App Brand Header
              Row(
                children: [
                  Container(
                    width: 38,
                    height: 38,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: AppColors.surface,
                      border: Border.all(color: AppColors.accent, width: 1.5),
                    ),
                    child: const Icon(Icons.shield_outlined, color: AppColors.accent, size: 20),
                  ),
                  const SizedBox(width: 12),
                  Text(AppConstants.appName, style: Theme.of(context).textTheme.displayLarge),
                ],
              ),
              const SizedBox(height: 6),
              Text(
                AppConstants.tagline,
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      color: AppColors.accent,
                      fontWeight: FontWeight.w600,
                    ),
              ),
              const SizedBox(height: 36),

              Text('Welcome back', style: Theme.of(context).textTheme.headlineMedium),
              const SizedBox(height: 8),
              Text(
                demo
                    ? 'Running in Demo Mode (offline / no google-services.json). Tap Quick Demo Login or enter any credentials.'
                    : 'Sign in with your registered Firebase account to analyze Python packages.',
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      color: AppColors.textSecondary,
                    ),
              ),
              const SizedBox(height: 24),

              // Email input with subtle focus glow
              PgTextField(
                controller: _email,
                label: 'Email',
                hint: 'you@lab.edu',
                keyboardType: TextInputType.emailAddress,
                prefixIcon: Icons.mail_outline,
                textInputAction: TextInputAction.next,
                onChanged: (_) => setState(() {}),
              ),
              const SizedBox(height: 14),

              // Password input with visibility toggle
              PgTextField(
                controller: _password,
                label: 'Password',
                obscure: true,
                prefixIcon: Icons.lock_outline,
                textInputAction: TextInputAction.done,
                onChanged: (_) => setState(() {}),
              ),

              // Dismissible Error Banner
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

              // Primary Sign In CTA (Disabled until email & password entered)
              PgButton(
                label: 'Sign in',
                loading: loading,
                onPressed: (_canSubmit && !loading) ? _submit : null,
              ),

              const SizedBox(height: 12),

              // Continue with Google
              OutlinedButton.icon(
                onPressed: loading
                    ? null
                    : () async {
                        final ok = await ref.read(authControllerProvider.notifier).signInWithGoogle();
                        if (ok && context.mounted) context.go('/dashboard');
                      },
                icon: const Icon(Icons.g_mobiledata, size: 24),
                label: const Text('Continue with Google'),
                style: OutlinedButton.styleFrom(
                  minimumSize: const Size.fromHeight(52),
                  side: const BorderSide(color: AppColors.border),
                  foregroundColor: AppColors.textPrimary,
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                ),
              ),

              const SizedBox(height: 12),

              // 1-Tap Quick Demo Login (Perfect for Viva evaluation)
              OutlinedButton.icon(
                onPressed: loading ? null : _demoLogin,
                icon: const Icon(Icons.bolt, color: AppColors.suspicious, size: 20),
                label: const Text('1-Tap Demo Login (Viva / Dev)'),
                style: OutlinedButton.styleFrom(
                  minimumSize: const Size.fromHeight(46),
                  side: BorderSide(color: AppColors.suspicious.withOpacity( 0.6)),
                  foregroundColor: AppColors.suspicious,
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                ),
              ),

              const SizedBox(height: 24),

              // Create Account Link
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const Text('New here? ', style: TextStyle(color: AppColors.textSecondary)),
                  GestureDetector(
                    onTap: () {
                      ref.read(authControllerProvider.notifier).clearError();
                      context.go('/signup');
                    },
                    child: const Text(
                      'Create account',
                      style: TextStyle(color: AppColors.accent, fontWeight: FontWeight.w600),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}
