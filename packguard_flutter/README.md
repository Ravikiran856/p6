# PackGuard Flutter (Android)

Dark cybersecurity UI for scanning PyPI packages. State management is **Riverpod**
everywhere (`ProviderScope` → feature `Notifier`s). The next prompt owns the
dependency-graph, full history, and settings implementations — those tabs are
wired as placeholders so the bottom nav is complete.

## Bootstrap (Flutter SDK required)

This repo ships the Dart source. Generate the Android native project once:

```bash
cd packguard_flutter
flutter create . --org com.packguard --platforms android
flutter pub get
```

Point the app at your API in `lib/core/constants/api_endpoints.dart`
(`http://10.0.2.2:8000` is the Android emulator alias for host localhost).

### Firebase

1. Add `google-services.json` under `android/app/`.
2. Apply the Google services Gradle plugin.
3. Enable Email/Password + Google in Firebase Console.

Until Firebase is configured the app falls back to **demo auth** (matches the
backend `ALLOW_DEV_AUTH_BYPASS=true` tokens of the form `dev:<uid>:<email>`).

### Android permissions

`flutter create` writes `AndroidManifest.xml`. Add:

```xml
<uses-permission android:name="android.permission.INTERNET"/>
<uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>
```

## Screens in this drop

- Splash → Login/Signup or Dashboard (auth stream)
- Dashboard (search, recent scans, `fl_chart` trend, bottom nav)
- Scan input (package vs requirements.txt)
- Live scan progress (min 1.5s/step, real API in parallel)
