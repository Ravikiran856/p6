import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Tiny session bag so Dio can attach Bearer tokens without importing AuthController
/// (avoids a circular provider dependency: Dio ↔ Auth).
class SessionState {
  const SessionState({
    this.uid,
    this.email,
    this.displayName,
    this.idToken,
  });

  final String? uid;
  final String? email;
  final String? displayName;
  final String? idToken;

  bool get isAuthenticated => idToken != null && idToken!.isNotEmpty;

  SessionState copyWith({
    String? uid,
    String? email,
    String? displayName,
    String? idToken,
    bool clear = false,
  }) {
    if (clear) return const SessionState();
    return SessionState(
      uid: uid ?? this.uid,
      email: email ?? this.email,
      displayName: displayName ?? this.displayName,
      idToken: idToken ?? this.idToken,
    );
  }
}

class SessionNotifier extends Notifier<SessionState> {
  @override
  SessionState build() => const SessionState();

  void setSession({
    required String uid,
    required String idToken,
    String? email,
    String? displayName,
  }) {
    state = SessionState(
      uid: uid,
      email: email,
      displayName: displayName,
      idToken: idToken,
    );
  }

  void clear() => state = const SessionState();
}

final sessionProvider = NotifierProvider<SessionNotifier, SessionState>(
  SessionNotifier.new,
);
