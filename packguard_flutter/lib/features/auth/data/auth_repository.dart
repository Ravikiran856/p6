import 'package:dio/dio.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter/foundation.dart';
import 'package:google_sign_in/google_sign_in.dart';

import '../../../core/constants/api_endpoints.dart';
import '../../../core/network/api_result.dart';

class AuthUser {
  const AuthUser({
    required this.uid,
    this.email,
    this.displayName,
    required this.idToken,
  });

  final String uid;
  final String? email;
  final String? displayName;
  final String idToken;
}

/// Wraps Firebase Auth (email + Google) and PackGuard's `/auth/*` token handshake.
///
/// If Firebase is not initialized (no google-services.json yet), [demoMode] is true
/// and we mint `dev:<uid>:<email>` tokens that the backend accepts when
/// ALLOW_DEV_AUTH_BYPASS=true.
class AuthRepository {
  AuthRepository({
    required this.dio,
    this.firebaseReady = false,
  });

  final Dio dio;
  final bool firebaseReady;
  final GoogleSignIn _google = GoogleSignIn(scopes: ['email']);

  bool get demoMode => !firebaseReady;

  Future<ApiResult<AuthUser>> signUpEmail(String email, String password) async {
    try {
      if (firebaseReady) {
        final cred = await FirebaseAuth.instance.createUserWithEmailAndPassword(
          email: email,
          password: password,
        );
        final token = await cred.user!.getIdToken();
        return _handshake(ApiEndpoints.signup, token ?? '', cred.user!);
      }
      return _demoHandshake(email, signup: true);
    } on FirebaseAuthException catch (e) {
      return ApiFailure(e.message ?? e.code);
    } catch (e) {
      return ApiFailure(e.toString());
    }
  }

  Future<ApiResult<AuthUser>> signInEmail(String email, String password) async {
    try {
      if (firebaseReady) {
        final cred = await FirebaseAuth.instance.signInWithEmailAndPassword(
          email: email,
          password: password,
        );
        final token = await cred.user!.getIdToken();
        return _handshake(ApiEndpoints.login, token ?? '', cred.user!);
      }
      return _demoHandshake(email, signup: false);
    } on FirebaseAuthException catch (e) {
      return ApiFailure(e.message ?? e.code);
    } catch (e) {
      return ApiFailure(e.toString());
    }
  }

  Future<ApiResult<AuthUser>> signInWithGoogle() async {
    try {
      if (!firebaseReady) {
        return const ApiFailure(
          'Google Sign-In needs Firebase (google-services.json). Use email or Demo.',
        );
      }
      final googleUser = await _google.signIn();
      if (googleUser == null) {
        return const ApiFailure('Google sign-in cancelled');
      }
      final googleAuth = await googleUser.authentication;
      final credential = GoogleAuthProvider.credential(
        accessToken: googleAuth.accessToken,
        idToken: googleAuth.idToken,
      );
      final cred = await FirebaseAuth.instance.signInWithCredential(credential);
      final token = await cred.user!.getIdToken();
      return _handshake(ApiEndpoints.login, token ?? '', cred.user!);
    } on FirebaseAuthException catch (e) {
      return ApiFailure(e.message ?? e.code);
    } catch (e) {
      return ApiFailure(e.toString());
    }
  }

  Future<void> signOut() async {
    if (firebaseReady) {
      await FirebaseAuth.instance.signOut();
      try {
        await _google.signOut();
      } catch (e) {
        debugPrint('Google signOut: $e');
      }
    }
  }

  /// Restores an existing Firebase Auth session upon app launch (e.g. from splash screen).
  ///
  /// VIVA NOTE:
  /// On app cold start, the Firebase client SDK caches credentials in device keystore.
  /// If a user is already signed in, we extract their fresh ID token and ping
  /// `/auth/login` so the backend registers the session and refreshes user metadata.
  /// Wrapped in try-catch so network hiccups during splash won't crash the application.
  Future<AuthUser?> restoreFirebaseSession() async {
    if (!firebaseReady) return null;
    try {
      final user = FirebaseAuth.instance.currentUser;
      if (user == null) return null;
      final token = await user.getIdToken();
      if (token == null) return null;

      try {
        await dio.post(
          ApiEndpoints.login,
          data: {'idToken': token},
        );
      } catch (e) {
        // Backend temporarily unreachable; allow user to proceed with cached token
        debugPrint('Backend handshake on restore skipped: $e');
      }

      return AuthUser(
        uid: user.uid,
        email: user.email,
        displayName: user.displayName ?? (user.email?.split('@').first),
        idToken: token,
      );
    } catch (e) {
      debugPrint('Error restoring Firebase session: $e');
      return null;
    }
  }

  /// Fast 1-tap demo sign-in for evaluation and viva presentations.
  ///
  /// VIVA NOTE:
  /// Uses the dev bypass token structure `dev:<uid>:<email>`. The FastAPI backend's
  /// `auth.py` validates this token format when `ALLOW_DEV_AUTH_BYPASS = true`.
  Future<ApiResult<AuthUser>> signInDemo({String email = 'analyst@packguard.dev'}) async {
    return _demoHandshake(email, signup: false);
  }

  Future<ApiResult<AuthUser>> _handshake(
    String path,
    String idToken,
    User firebaseUser,
  ) async {
    try {
      final res = await dio.post(path, data: {'idToken': idToken});
      final data = res.data as Map<String, dynamic>;
      return ApiSuccess(
        AuthUser(
          uid: data['uid'] as String? ?? firebaseUser.uid,
          email: data['email'] as String? ?? firebaseUser.email,
          displayName: data['displayName'] as String? ?? firebaseUser.displayName,
          idToken: idToken,
        ),
      );
    } on DioException catch (e) {
      // Signup 409 → already registered; fall through to login.
      if (e.response?.statusCode == 409) {
        return _handshake(ApiEndpoints.login, idToken, firebaseUser);
      }
      return ApiFailure(_dioMessage(e), statusCode: e.response?.statusCode);
    }
  }

  Future<ApiResult<AuthUser>> _demoHandshake(String email, {required bool signup}) async {
    final uid = email.split('@').first.replaceAll(RegExp(r'[^a-zA-Z0-9]'), '-');
    final token = 'dev:$uid:$email';
    try {
      final path = signup ? ApiEndpoints.signup : ApiEndpoints.login;
      final res = await dio.post(path, data: {'idToken': token});
      final data = res.data as Map<String, dynamic>;
      return ApiSuccess(
        AuthUser(
          uid: data['uid'] as String? ?? uid,
          email: data['email'] as String? ?? email,
          displayName: data['displayName'] as String?,
          idToken: token,
        ),
      );
    } on DioException catch (e) {
      if (e.response?.statusCode == 409) {
        return _demoHandshake(email, signup: false);
      }
      // Offline / backend down: still let the student demo the UI.
      return ApiSuccess(
        AuthUser(uid: uid, email: email, displayName: 'Demo User', idToken: token),
      );
    }
  }

  String _dioMessage(DioException e) {
    final data = e.response?.data;
    if (data is Map && data['detail'] != null) return data['detail'].toString();
    if (data is Map && data['error'] is Map) {
      return (data['error']['message'] ?? e.message).toString();
    }
    return e.message ?? 'Network error';
  }
}
