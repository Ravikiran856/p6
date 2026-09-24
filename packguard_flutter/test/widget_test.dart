import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'package:packguard/app.dart';
import 'package:packguard/features/auth/application/auth_providers.dart';

void main() {
  testWidgets('PackGuard boots to splash', (tester) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          firebaseReadyProvider.overrideWithValue(false),
        ],
        child: const PackGuardApp(),
      ),
    );
    expect(find.text('PackGuard'), findsOneWidget);
    expect(find.text('Scan Smart. Ship Safe.'), findsOneWidget);
  });
}
