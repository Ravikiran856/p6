import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/network/api_result.dart';
import '../../../core/network/dio_client.dart';
import '../../../core/session/session_provider.dart';
import '../data/auth_repository.dart';

final firebaseReadyProvider = Provider<bool>((ref) => false);

final authRepositoryProvider = Provider<AuthRepository>((ref) {
  return AuthRepository(
    dio: ref.watch(dioProvider),
    firebaseReady: ref.watch(firebaseReadyProvider),
  );
});

class AuthController extends Notifier<AsyncValue<void>> {
  @override
  AsyncValue<void> build() => const AsyncData(null);

  AuthRepository get _repo => ref.read(authRepositoryProvider);

  Future<bool> signIn(String email, String password) async {
    state = const AsyncLoading();
    final result = await _repo.signInEmail(email.trim(), password);
    return _apply(result);
  }

  Future<bool> signUp(String email, String password) async {
    state = const AsyncLoading();
    final result = await _repo.signUpEmail(email.trim(), password);
    return _apply(result);
  }

  Future<bool> signInWithGoogle() async {
    state = const AsyncLoading();
    final result = await _repo.signInWithGoogle();
    return _apply(result);
  }

  /// 1-tap demo sign-in for testing/viva demonstration
  Future<bool> signInDemo([String email = 'analyst@packguard.dev']) async {
    state = const AsyncLoading();
    final result = await _repo.signInDemo(email: email);
    return _apply(result);
  }

  /// Clears any transient error message
  void clearError() {
    if (state.hasError) {
      state = const AsyncData(null);
    }
  }

  Future<void> restore() async {
    final user = await _repo.restoreFirebaseSession();
    if (user != null) {
      ref.read(sessionProvider.notifier).setSession(
            uid: user.uid,
            idToken: user.idToken,
            email: user.email,
            displayName: user.displayName,
          );
    }
  }

  Future<void> signOut() async {
    await _repo.signOut();
    ref.read(sessionProvider.notifier).clear();
    state = const AsyncData(null);
  }

  bool _apply(ApiResult<AuthUser> result) {
    if (result is ApiSuccess<AuthUser>) {
        ref.read(sessionProvider.notifier).setSession(
              uid: result.data.uid,
              idToken: result.data.idToken,
              email: result.data.email,
              displayName: result.data.displayName,
            );
        state = const AsyncData(null);
        return true;
    }
    if (result is ApiFailure<AuthUser>) {
        state = AsyncError(result.message, StackTrace.current);
        return false;
    }
    return false;
  }
}

final authControllerProvider =
    NotifierProvider<AuthController, AsyncValue<void>>(AuthController.new);
