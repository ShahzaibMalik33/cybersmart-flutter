// lib/main.dart

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'services/phishing_detector.dart';
import 'screens/scanner_screen.dart';
import 'screens/text_scanner_screen.dart';
import 'screens/file_scanner_screen.dart';
import 'screens/history_screen.dart';
import 'widgets/shared_widgets.dart';
import 'package:cybersmart/services/phishing_model.dart';


void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  await SystemChrome.setPreferredOrientations([
    DeviceOrientation.portraitUp,
    DeviceOrientation.portraitDown,
  ]);

  SystemChrome.setSystemUIOverlayStyle(const SystemUiOverlayStyle(
    statusBarColor:          Colors.transparent,
    statusBarIconBrightness: Brightness.light,
  ));

  await PhishingDetector.init();
  runApp(const CyberSmartApp());
}

class CyberSmartApp extends StatelessWidget {
  const CyberSmartApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'CyberSmart',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: AppColors.accent,
          brightness: Brightness.dark,
        ).copyWith(surface: AppColors.bg),
        scaffoldBackgroundColor: AppColors.bg,
        fontFamily: 'Roboto',
        useMaterial3: true,
      ),
      home: const _HomeShell(),
    );
  }
}

class _HomeShell extends StatefulWidget {
  const _HomeShell();
  @override
  State<_HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<_HomeShell> {
  int _idx = 0;

  static const _screens = [
    ScannerScreen(),
    TextScannerScreen(),
    FileScannerScreen(),
    HistoryScreen(),
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.bg,
      body: IndexedStack(
        index: _idx,
        children: _screens,
      ),
      bottomNavigationBar: Container(
        decoration: const BoxDecoration(
          color: AppColors.surface,
          border: Border(
            top: BorderSide(color: AppColors.cardBorder, width: 1),
          ),
        ),
        child: SafeArea(
          child: Padding(
            padding: const EdgeInsets.symmetric(vertical: 6),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceAround,
              children: [
                _NavItem(
                  icon:   Icons.radar,
                  label:  'URL',
                  active: _idx == 0,
                  color:  AppColors.accent,
                  onTap:  () => setState(() => _idx = 0),
                ),
                _NavItem(
                  icon:   Icons.sms_outlined,
                  label:  'SMS',
                  active: _idx == 1,
                  color:  AppColors.safe,
                  onTap:  () => setState(() => _idx = 1),
                ),
                _NavItem(
                  icon:   Icons.shield_outlined,
                  label:  'Files',
                  active: _idx == 2,
                  color:  const Color(0xFF8B5CF6),
                  onTap:  () => setState(() => _idx = 2),
                ),
                _NavItem(
                  icon:   Icons.history,
                  label:  'History',
                  active: _idx == 3,
                  color:  AppColors.warning,
                  onTap:  () => setState(() => _idx = 3),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _NavItem extends StatelessWidget {
  final IconData icon;
  final String label;
  final bool active;
  final Color color;
  final VoidCallback onTap;
  const _NavItem({
    required this.icon,
    required this.label,
    required this.active,
    required this.color,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final c = active ? color : AppColors.textSecondary;
    return GestureDetector(
      onTap: onTap,
      behavior: HitTestBehavior.opaque,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 7),
        decoration: BoxDecoration(
          color: active ? color.withOpacity(0.12) : Colors.transparent,
          borderRadius: BorderRadius.circular(14),
          border: Border.all(
            color: active ? color.withOpacity(0.3) : Colors.transparent,
          ),
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, color: c, size: 22),
            const SizedBox(height: 4),
            Text(label,
                style: TextStyle(
                    color: c,
                    fontSize: 11,
                    fontWeight:
                        active ? FontWeight.w600 : FontWeight.normal)),
          ],
        ),
      ),
    );
  }
}
