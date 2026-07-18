// lib/screens/file_scanner_screen.dart

import 'dart:io';
import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import '../models/file_scan_result.dart';
import '../services/virustotal_service.dart';
import '../services/file_history_service.dart';
import '../widgets/shared_widgets.dart';

class FileScannerScreen extends StatefulWidget {
  const FileScannerScreen({super.key});
  @override
  State<FileScannerScreen> createState() => _FileScannerScreenState();
}

class _FileScannerScreenState extends State<FileScannerScreen>
    with SingleTickerProviderStateMixin {
  FileScanResult? _result;
  String  _stage     = '';   // uploading / checking / scanning / parsing
  bool    _scanning  = false;
  String? _error;

  late AnimationController _pulseCtrl;
  late Animation<double>   _pulseAnim;

  // Supported types config
  static const _supportedTypes = {
    'pdf':  _FileType('PDF Document',     Icons.picture_as_pdf_outlined, Color(0xFFEF4444)),
    'doc':  _FileType('Word Document',    Icons.description_outlined,     Color(0xFF3B82F6)),
    'docx': _FileType('Word Document',    Icons.description_outlined,     Color(0xFF3B82F6)),
    'exe':  _FileType('Executable File',  Icons.terminal_outlined,        Color(0xFFF59E0B)),
    'apk':  _FileType('Android APK',      Icons.android_outlined,         Color(0xFF22C55E)),
    'zip':  _FileType('ZIP Archive',      Icons.folder_zip_outlined,      Color(0xFF8B5CF6)),
    'rar':  _FileType('RAR Archive',      Icons.folder_zip_outlined,      Color(0xFF8B5CF6)),
    'msi':  _FileType('Installer (MSI)',  Icons.install_desktop_outlined, Color(0xFFF59E0B)),
    'bat':  _FileType('Batch Script',     Icons.code_outlined,            Color(0xFFEC4899)),
    'ps1':  _FileType('PowerShell Script',Icons.code_outlined,            Color(0xFF60A5FA)),
  };

  @override
  void initState() {
    super.initState();
    _pulseCtrl = AnimationController(
        vsync: this, duration: const Duration(seconds: 2))
      ..repeat(reverse: true);
    _pulseAnim = Tween(begin: 0.5, end: 1.0).animate(
        CurvedAnimation(parent: _pulseCtrl, curve: Curves.easeInOut));
  }

  @override
  void dispose() {
    _pulseCtrl.dispose();
    super.dispose();
  }

  // ── File picker ───────────────────────────────────────────────
  Future<void> _pickAndScan() async {
    try {
      final result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: [
          'pdf', 'doc', 'docx', 'exe', 'apk',
          'zip', 'rar', 'msi', 'bat', 'ps1',
        ],
        allowMultiple: false,
        withData: false,
      );

      if (result == null || result.files.isEmpty) return;
      final picked = result.files.first;
      if (picked.path == null) {
        setState(() => _error = 'Could not access file path. Try again.');
        return;
      }

      await _scanFile(picked.path!, picked.name, picked.size);
    } catch (e) {
      setState(() => _error = 'File picker error: $e');
    }
  }

  // ── Scan logic ────────────────────────────────────────────────
  Future<void> _scanFile(
      String path, String name, int size) async {
    final ext    = name.split('.').last.toLowerCase();
    final ftInfo = _supportedTypes[ext] ??
        const _FileType('File', Icons.insert_drive_file_outlined,
            Color(0xFF64748B));

    setState(() {
      _scanning = true;
      _result   = null;
      _error    = null;
      _stage    = 'preparing';
    });

    // Build initial result (pending)
    final initial = FileScanResult(
      fileName:  name,
      filePath:  path,
      fileType:  _extToType(ext),
      fileSize:  size,
      sha256:    '',
      scannedAt: DateTime.now(),
      vtStatus:  'pending',
      verdict:   'Unknown',
      threatName: '',
    );
    setState(() => _result = initial);
    await FileHistoryService.add(initial);

    // Run VT file scan
    final vt = await VirusTotalService.scanFile(
      path,
      onStage: (s) {
        if (mounted) setState(() => _stage = s);
      },
    );

    final updated = initial.copyWith(
      vtStatus:    vt['status'],
      vtMalicious:  vt['malicious'],
      vtSuspicious: vt['suspicious'],
      vtClean:      vt['clean'],
      vtUndetected: vt['undetected'],
      vtTotal:      vt['total'],
      vtPermalink:  vt['permalink'],
      vtError:      vt['error'],
      verdict:      vt['verdict']    ?? 'Unknown',
      threatName:   vt['threatName'] ?? '',
    );

    await FileHistoryService.update(updated);

    if (mounted) {
      setState(() {
        _result   = updated;
        _scanning = false;
        _stage    = '';
        if (vt['status'] == 'error') _error = vt['error'];
      });
    }
  }

  void _clear() => setState(() {
    _result   = null;
    _error    = null;
    _scanning = false;
    _stage    = '';
  });

  String _extToType(String ext) {
    switch (ext) {
      case 'pdf':         return 'pdf';
      case 'doc':
      case 'docx':        return 'word';
      case 'exe':
      case 'msi':
      case 'bat':
      case 'ps1':         return 'exe';
      case 'apk':         return 'apk';
      case 'zip':
      case 'rar':         return 'zip';
      default:            return 'other';
    }
  }

  String _stageLabel(String s) {
    switch (s) {
      case 'preparing':  return 'Preparing file...';
      case 'checking':   return 'Checking VT database...';
      case 'uploading':  return 'Uploading to VirusTotal...';
      case 'scanning':   return 'Running 70+ antivirus engines...';
      case 'parsing':    return 'Parsing results...';
      default:           return 'Processing...';
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.bg,
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SizedBox(height: 8),

              // ── Header ─────────────────────────────────────────
              _Header(pulseAnim: _pulseAnim, scanning: _scanning),

              const SizedBox(height: 22),

              // ── Supported file types ────────────────────────────
              if (!_scanning && _result == null && _error == null)
                _SupportedTypesGrid(),

              // ── Drop zone / Pick button ─────────────────────────
              if (!_scanning && _result == null)
                _PickZone(onPick: _pickAndScan),

              // ── Error ───────────────────────────────────────────
              if (_error != null && !_scanning) ...[
                const SizedBox(height: 16),
                _ErrorCard(message: _error!),
                const SizedBox(height: 12),
                Center(
                  child: _OutlineButton(
                    icon: Icons.refresh,
                    label: 'Try Another File',
                    onTap: _clear,
                  ),
                ),
              ],

              // ── Scanning progress ────────────────────────────────
              if (_scanning) ...[
                const SizedBox(height: 8),
                _ScanningProgress(
                  stage:     _stage,
                  stageLabel: _stageLabel(_stage),
                  result:    _result,
                ),
              ],

              // ── Result ───────────────────────────────────────────
              if (_result != null && !_scanning &&
                  _result!.vtStatus == 'done') ...[
                const SizedBox(height: 8),
                _VerdictCard(r: _result!),
                const SizedBox(height: 14),
                _EngineStatsCard(r: _result!),
                const SizedBox(height: 14),
                _FileInfoCard(r: _result!),
                const SizedBox(height: 14),
                if (_result!.threatName.isNotEmpty)
                  _ThreatNameCard(threatName: _result!.threatName),
                if (_result!.threatName.isNotEmpty)
                  const SizedBox(height: 14),
                _ActionRow(
                  onScanAnother: _clear,
                  permalink: _result!.vtPermalink,
                ),
              ],

              // ── Error result (after scan attempt) ───────────────
              if (_result != null && !_scanning &&
                  _result!.vtStatus == 'error') ...[
                const SizedBox(height: 8),
                _FileInfoCard(r: _result!),
                const SizedBox(height: 12),
                _ErrorCard(
                    message: _result!.vtError ??
                        'VirusTotal scan failed. Check internet connection.'),
                const SizedBox(height: 14),
                Center(
                  child: _OutlineButton(
                    icon: Icons.refresh,
                    label: 'Retry Scan',
                    onTap: () => _scanFile(
                        _result!.filePath,
                        _result!.fileName,
                        _result!.fileSize),
                  ),
                ),
              ],

              const SizedBox(height: 30),
            ],
          ),
        ),
      ),
    );
  }
}

// ── Supporting record ────────────────────────────────────────────
class _FileType {
  final String label;
  final IconData icon;
  final Color color;
  const _FileType(this.label, this.icon, this.color);
}

// ══════════════════════════════════════════════════════════════════
// ── Sub-widgets ───────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════

class _Header extends StatelessWidget {
  final Animation<double> pulseAnim;
  final bool scanning;
  const _Header({required this.pulseAnim, required this.scanning});

  @override
  Widget build(BuildContext context) => Row(children: [
    AnimatedBuilder(
      animation: pulseAnim,
      builder: (_, child) => Opacity(
          opacity: scanning ? pulseAnim.value : 1.0, child: child),
      child: Container(
        width: 52, height: 52,
        decoration: BoxDecoration(
          gradient: const LinearGradient(
            colors: [Color(0xFF8B5CF6), Color(0xFFEC4899)],
          ),
          borderRadius: BorderRadius.circular(14),
          boxShadow: [BoxShadow(
            color: const Color(0xFF8B5CF6).withOpacity(0.4),
            blurRadius: 14, offset: const Offset(0, 4))],
        ),
        child: const Icon(Icons.shield_outlined,
            color: Colors.white, size: 28),
      ),
    ),
    const SizedBox(width: 14),
    Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      const Text('File Scanner',
          style: TextStyle(
              color: AppColors.textPrimary,
              fontSize: 22,
              fontWeight: FontWeight.bold)),
      Row(children: [
        _Dot(AppColors.vtColor),
        const SizedBox(width: 5),
        const Text('VirusTotal 70+ Engines',
            style: TextStyle(color: AppColors.vtColor, fontSize: 12)),
        const SizedBox(width: 10),
        _Dot(AppColors.safe),
        const SizedBox(width: 5),
        const Text('32 MB Max',
            style: TextStyle(color: AppColors.safe, fontSize: 12)),
      ]),
    ]),
  ]);
}

class _Dot extends StatelessWidget {
  final Color color;
  const _Dot(this.color);
  @override
  Widget build(BuildContext context) => Container(
    width: 7, height: 7,
    decoration: BoxDecoration(
      shape: BoxShape.circle,
      color: color,
      boxShadow: [BoxShadow(
          color: color.withOpacity(0.5), blurRadius: 4, spreadRadius: 1)],
    ),
  );
}

// ── Supported file types grid ─────────────────────────────────────
class _SupportedTypesGrid extends StatelessWidget {
  static const _types = [
    _TypeChip(Icons.picture_as_pdf_outlined,   'PDF',         Color(0xFFEF4444)),
    _TypeChip(Icons.description_outlined,       'Word / DOC',  Color(0xFF3B82F6)),
    _TypeChip(Icons.terminal_outlined,          'EXE / MSI',   Color(0xFFF59E0B)),
    _TypeChip(Icons.android_outlined,           'APK',         Color(0xFF22C55E)),
    _TypeChip(Icons.folder_zip_outlined,        'ZIP / RAR',   Color(0xFF8B5CF6)),
    _TypeChip(Icons.code_outlined,              'BAT / PS1',   Color(0xFFEC4899)),
  ];

  const _SupportedTypesGrid();

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      const Text('Supported File Types',
          style: TextStyle(
              color: AppColors.textSecondary,
              fontSize: 12,
              fontWeight: FontWeight.w500,
              letterSpacing: 0.5)),
      const SizedBox(height: 10),
      GridView.count(
        crossAxisCount: 3,
        shrinkWrap: true,
        physics: const NeverScrollableScrollPhysics(),
        crossAxisSpacing: 10,
        mainAxisSpacing: 10,
        childAspectRatio: 2.2,
        children: _types,
      ),
      const SizedBox(height: 20),
    ],
  );
}

class _TypeChip extends StatelessWidget {
  final IconData icon;
  final String label;
  final Color color;
  const _TypeChip(this.icon, this.label, this.color);

  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
    decoration: BoxDecoration(
      color: color.withOpacity(0.08),
      borderRadius: BorderRadius.circular(10),
      border: Border.all(color: color.withOpacity(0.25)),
    ),
    child: Row(children: [
      Icon(icon, color: color, size: 15),
      const SizedBox(width: 6),
      Expanded(
        child: Text(label,
            style: TextStyle(
                color: color,
                fontSize: 11,
                fontWeight: FontWeight.w600),
            overflow: TextOverflow.ellipsis),
      ),
    ]),
  );
}

// ── Pick zone ─────────────────────────────────────────────────────
class _PickZone extends StatelessWidget {
  final VoidCallback onPick;
  const _PickZone({required this.onPick});

  @override
  Widget build(BuildContext context) => GestureDetector(
    onTap: onPick,
    child: Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(vertical: 40, horizontal: 20),
      decoration: BoxDecoration(
        color: AppColors.card,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
          color: AppColors.vtColor.withOpacity(0.4),
          width: 1.5,
          strokeAlign: BorderSide.strokeAlignInside,
        ),
        gradient: LinearGradient(
          colors: [
            AppColors.vtColor.withOpacity(0.06),
            AppColors.accent.withOpacity(0.04),
          ],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
      ),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Container(
            width: 64, height: 64,
            decoration: BoxDecoration(
              color: AppColors.vtColor.withOpacity(0.12),
              shape: BoxShape.circle,
              border: Border.all(
                  color: AppColors.vtColor.withOpacity(0.3), width: 2),
            ),
            child: const Icon(Icons.cloud_upload_outlined,
                color: AppColors.vtColor, size: 30),
          ),
          const SizedBox(height: 16),
          const Text('Tap to Select a File',
              style: TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 17,
                  fontWeight: FontWeight.bold)),
          const SizedBox(height: 6),
          const Text('PDF, Word, EXE, APK, ZIP, BAT, PS1',
              style: TextStyle(
                  color: AppColors.textSecondary, fontSize: 13)),
          const SizedBox(height: 14),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
            decoration: BoxDecoration(
              color: AppColors.vtColor.withOpacity(0.15),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(
                  color: AppColors.vtColor.withOpacity(0.4)),
            ),
            child: const Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(Icons.biotech_outlined,
                    color: AppColors.vtColor, size: 16),
                SizedBox(width: 8),
                Text('Scanned by 70+ Antivirus Engines',
                    style: TextStyle(
                        color: AppColors.vtColor,
                        fontSize: 13,
                        fontWeight: FontWeight.w600)),
              ],
            ),
          ),
          const SizedBox(height: 8),
          const Text('Max file size: 32 MB',
              style: TextStyle(
                  color: AppColors.textSecondary, fontSize: 11)),
        ],
      ),
    ),
  );
}

// ── Scanning progress card ────────────────────────────────────────
class _ScanningProgress extends StatelessWidget {
  final String stage, stageLabel;
  final FileScanResult? result;
  const _ScanningProgress({
    required this.stage,
    required this.stageLabel,
    required this.result,
  });

  static const _stages = [
    'preparing', 'checking', 'uploading', 'scanning', 'parsing',
  ];

  @override
  Widget build(BuildContext context) {
    final stageIdx = _stages.indexOf(stage).clamp(0, _stages.length - 1);

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(22),
      decoration: BoxDecoration(
        color: AppColors.card,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
            color: AppColors.vtColor.withOpacity(0.35), width: 1.5),
        gradient: LinearGradient(
          colors: [
            AppColors.vtColor.withOpacity(0.08),
            AppColors.accent.withOpacity(0.04),
          ],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
      ),
      child: Column(
        children: [
          // Animated scanner icon
          const SizedBox(
            width: 60, height: 60,
            child: CircularProgressIndicator(
              color: AppColors.vtColor,
              strokeWidth: 3,
            ),
          ),
          const SizedBox(height: 18),

          // File name if available
          if (result != null) ...[
            Row(mainAxisAlignment: MainAxisAlignment.center, children: [
              Icon(_fileIcon(result!.fileType),
                  color: AppColors.vtColor, size: 18),
              const SizedBox(width: 8),
              Flexible(
                child: Text(
                  result!.fileName,
                  style: const TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 14,
                      fontWeight: FontWeight.w600),
                  overflow: TextOverflow.ellipsis,
                  textAlign: TextAlign.center,
                ),
              ),
            ]),
            const SizedBox(height: 4),
            Text(result!.fileSizeFormatted,
                style: const TextStyle(
                    color: AppColors.textSecondary, fontSize: 12)),
            const SizedBox(height: 16),
          ],

          Text(stageLabel,
              style: const TextStyle(
                  color: AppColors.vtColor,
                  fontSize: 15,
                  fontWeight: FontWeight.w600)),
          const SizedBox(height: 6),
          const Text(
            'VirusTotal is checking your file\nagainst 70+ antivirus engines',
            textAlign: TextAlign.center,
            style: TextStyle(
                color: AppColors.textSecondary, fontSize: 12),
          ),
          const SizedBox(height: 20),

          // Stage progress dots
          Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: List.generate(_stages.length, (i) {
              final done   = i < stageIdx;
              final active = i == stageIdx;
              final color  = done || active
                  ? AppColors.vtColor
                  : AppColors.textMuted;
              return AnimatedContainer(
                duration: const Duration(milliseconds: 300),
                margin: const EdgeInsets.symmetric(horizontal: 4),
                width:  active ? 24 : 8,
                height: 8,
                decoration: BoxDecoration(
                  color: color.withOpacity(active ? 1.0 : done ? 0.6 : 0.2),
                  borderRadius: BorderRadius.circular(4),
                ),
              );
            }),
          ),
          const SizedBox(height: 14),

          // Stage labels row
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: _stages.asMap().entries.map((e) {
              final idx    = e.key;
              final s      = e.value;
              final active = idx == stageIdx;
              final done   = idx < stageIdx;
              return Expanded(
                child: Column(children: [
                  Icon(
                    done
                        ? Icons.check_circle
                        : active
                            ? Icons.radio_button_checked
                            : Icons.radio_button_unchecked,
                    color: done
                        ? AppColors.safe
                        : active
                            ? AppColors.vtColor
                            : AppColors.textMuted,
                    size: 14,
                  ),
                  const SizedBox(height: 3),
                  Text(
                    _stageShortLabel(s),
                    style: TextStyle(
                      color: done
                          ? AppColors.safe
                          : active
                              ? AppColors.vtColor
                              : AppColors.textMuted,
                      fontSize: 9,
                    ),
                    textAlign: TextAlign.center,
                  ),
                ]),
              );
            }).toList(),
          ),
        ],
      ),
    );
  }

  String _stageShortLabel(String s) {
    switch (s) {
      case 'preparing': return 'Prepare';
      case 'checking':  return 'Check';
      case 'uploading': return 'Upload';
      case 'scanning':  return 'Scan';
      case 'parsing':   return 'Parse';
      default:          return s;
    }
  }

  IconData _fileIcon(String t) {
    switch (t) {
      case 'pdf':  return Icons.picture_as_pdf_outlined;
      case 'word': return Icons.description_outlined;
      case 'exe':  return Icons.terminal_outlined;
      case 'apk':  return Icons.android_outlined;
      case 'zip':  return Icons.folder_zip_outlined;
      default:     return Icons.insert_drive_file_outlined;
    }
  }
}

// ── Verdict card ──────────────────────────────────────────────────
class _VerdictCard extends StatelessWidget {
  final FileScanResult r;
  const _VerdictCard({required this.r});

  @override
  Widget build(BuildContext context) {
    final isMal  = r.isMalicious;
    final isSusp = r.isSuspicious;
    final color  = isMal
        ? AppColors.phishing
        : isSusp
            ? AppColors.warning
            : AppColors.safe;
    final icon   = isMal
        ? Icons.dangerous_outlined
        : isSusp
            ? Icons.warning_amber_outlined
            : Icons.verified_user_outlined;
    final title  = isMal
        ? '🚨 Malicious File Detected!'
        : isSusp
            ? '⚠️ Suspicious File'
            : '✅ File is Clean';
    final sub    = isMal
        ? 'This file is flagged as malware — do NOT open it'
        : isSusp
            ? 'Some engines flagged this file — proceed carefully'
            : 'No threats detected by any engine';

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [color.withOpacity(0.14), color.withOpacity(0.04)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: color.withOpacity(0.4), width: 1.5),
      ),
      child: Row(children: [
        Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: color.withOpacity(0.15),
            borderRadius: BorderRadius.circular(14),
          ),
          child: Icon(icon, color: color, size: 34),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(title,
                  style: TextStyle(
                      color: color,
                      fontSize: 17,
                      fontWeight: FontWeight.bold)),
              const SizedBox(height: 4),
              Text(sub,
                  style: const TextStyle(
                      color: AppColors.textSecondary, fontSize: 13)),
              const SizedBox(height: 10),
              Row(children: [
                _VtBadge('${(r.vtMalicious ?? 0) + (r.vtSuspicious ?? 0)}'
                    ' / ${r.vtTotal ?? 0} engines flagged', color),
              ]),
            ],
          ),
        ),
      ]),
    );
  }
}

class _VtBadge extends StatelessWidget {
  final String text;
  final Color color;
  const _VtBadge(this.text, this.color);
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 4),
    decoration: BoxDecoration(
      color: color.withOpacity(0.1),
      borderRadius: BorderRadius.circular(8),
      border: Border.all(color: color.withOpacity(0.3)),
    ),
    child: Text(text,
        style: TextStyle(
            color: color,
            fontSize: 11,
            fontWeight: FontWeight.w600)),
  );
}

// ── Engine stats card ─────────────────────────────────────────────
class _EngineStatsCard extends StatelessWidget {
  final FileScanResult r;
  const _EngineStatsCard({required this.r});

  @override
  Widget build(BuildContext context) {
    final malicious  = r.vtMalicious  ?? 0;
    final suspicious = r.vtSuspicious ?? 0;
    final clean      = r.vtClean      ?? 0;
    final undetected = r.vtUndetected ?? 0;
    final total      = r.vtTotal      ?? 1;
    final flagged    = malicious + suspicious;

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppColors.card,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppColors.cardBorder),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          Row(children: [
            const Icon(Icons.biotech_outlined,
                color: AppColors.vtColor, size: 16),
            const SizedBox(width: 7),
            const Text('Engine Analysis',
                style: TextStyle(
                    color: AppColors.vtColor,
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                    letterSpacing: 0.4)),
            const Spacer(),
            Text('$total engines total',
                style: const TextStyle(
                    color: AppColors.textSecondary, fontSize: 11)),
          ]),
          const SizedBox(height: 14),

          // 4-stat row
          Row(children: [
            _EngineStat('$malicious',  'Malicious',   AppColors.phishing),
            const SizedBox(width: 8),
            _EngineStat('$suspicious', 'Suspicious',  AppColors.warning),
            const SizedBox(width: 8),
            _EngineStat('$clean',      'Clean',       AppColors.safe),
            const SizedBox(width: 8),
            _EngineStat('$undetected', 'Undetected',  AppColors.textSecondary),
          ]),

          const SizedBox(height: 14),

          // Stacked progress bar
          ClipRRect(
            borderRadius: BorderRadius.circular(6),
            child: Row(children: [
              if (malicious > 0)
                Expanded(
                  flex: malicious,
                  child: Container(
                      height: 10,
                      color: AppColors.phishing),
                ),
              if (suspicious > 0)
                Expanded(
                  flex: suspicious,
                  child: Container(
                      height: 10,
                      color: AppColors.warning),
                ),
              if (clean > 0)
                Expanded(
                  flex: clean,
                  child: Container(
                      height: 10,
                      color: AppColors.safe),
                ),
              if (undetected > 0)
                Expanded(
                  flex: undetected,
                  child: Container(
                      height: 10,
                      color: AppColors.textMuted),
                ),
            ]),
          ),
          const SizedBox(height: 8),

          // Legend row
          Row(children: [
            _Legend(AppColors.phishing, 'Malicious'),
            const SizedBox(width: 12),
            _Legend(AppColors.warning,  'Suspicious'),
            const SizedBox(width: 12),
            _Legend(AppColors.safe,     'Clean'),
            const SizedBox(width: 12),
            _Legend(AppColors.textMuted,'Undetected'),
          ]),
        ],
      ),
    );
  }
}

class _EngineStat extends StatelessWidget {
  final String val, label;
  final Color color;
  const _EngineStat(this.val, this.label, this.color);
  @override
  Widget build(BuildContext context) => Expanded(
    child: Container(
      padding: const EdgeInsets.symmetric(vertical: 10),
      decoration: BoxDecoration(
        color: color.withOpacity(0.08),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withOpacity(0.2)),
      ),
      child: Column(children: [
        Text(val,
            style: TextStyle(
                color: color,
                fontSize: 18,
                fontWeight: FontWeight.bold)),
        const SizedBox(height: 2),
        Text(label,
            style: const TextStyle(
                color: AppColors.textSecondary, fontSize: 10)),
      ]),
    ),
  );
}

class _Legend extends StatelessWidget {
  final Color color;
  final String label;
  const _Legend(this.color, this.label);
  @override
  Widget build(BuildContext context) => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      Container(
          width: 8, height: 8,
          decoration: BoxDecoration(
              color: color, borderRadius: BorderRadius.circular(2))),
      const SizedBox(width: 4),
      Text(label,
          style: const TextStyle(
              color: AppColors.textSecondary, fontSize: 10)),
    ],
  );
}

// ── File info card ────────────────────────────────────────────────
class _FileInfoCard extends StatelessWidget {
  final FileScanResult r;
  const _FileInfoCard({required this.r});

  IconData get _icon {
    switch (r.fileType) {
      case 'pdf':  return Icons.picture_as_pdf_outlined;
      case 'word': return Icons.description_outlined;
      case 'exe':  return Icons.terminal_outlined;
      case 'apk':  return Icons.android_outlined;
      case 'zip':  return Icons.folder_zip_outlined;
      default:     return Icons.insert_drive_file_outlined;
    }
  }

  Color get _color {
    switch (r.fileType) {
      case 'pdf':  return AppColors.phishing;
      case 'word': return AppColors.accent;
      case 'exe':  return AppColors.warning;
      case 'apk':  return AppColors.safe;
      case 'zip':  return AppColors.vtColor;
      default:     return AppColors.textSecondary;
    }
  }

  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.all(14),
    decoration: BoxDecoration(
      color: AppColors.card,
      borderRadius: BorderRadius.circular(14),
      border: Border.all(color: AppColors.cardBorder),
    ),
    child: Column(children: [
      Row(children: [
        Container(
          padding: const EdgeInsets.all(10),
          decoration: BoxDecoration(
            color: _color.withOpacity(0.12),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(_icon, color: _color, size: 22),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(r.fileName,
                  style: const TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 14,
                      fontWeight: FontWeight.w600),
                  overflow: TextOverflow.ellipsis),
              const SizedBox(height: 2),
              Text('${r.fileTypeLabel}  •  ${r.fileSizeFormatted}',
                  style: const TextStyle(
                      color: AppColors.textSecondary, fontSize: 12)),
            ],
          ),
        ),
      ]),
      if (r.sha256.isNotEmpty) ...[
        const SizedBox(height: 10),
        const Divider(color: AppColors.cardBorder, height: 1),
        const SizedBox(height: 10),
        Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('SHA-256:',
                style: TextStyle(
                    color: AppColors.textSecondary,
                    fontSize: 11,
                    fontWeight: FontWeight.w500)),
            const SizedBox(width: 8),
            Expanded(
              child: Text(r.sha256,
                  style: const TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 10,
                      fontFamily: 'monospace'),
                  overflow: TextOverflow.ellipsis,
                  maxLines: 2),
            ),
          ],
        ),
      ],
    ]),
  );
}

// ── Threat name card ──────────────────────────────────────────────
class _ThreatNameCard extends StatelessWidget {
  final String threatName;
  const _ThreatNameCard({required this.threatName});
  @override
  Widget build(BuildContext context) => Container(
    width: double.infinity,
    padding: const EdgeInsets.all(14),
    decoration: BoxDecoration(
      color: AppColors.phishing.withOpacity(0.07),
      borderRadius: BorderRadius.circular(12),
      border: Border.all(
          color: AppColors.phishing.withOpacity(0.3)),
    ),
    child: Row(children: [
      const Icon(Icons.bug_report_outlined,
          color: AppColors.phishing, size: 20),
      const SizedBox(width: 10),
      Expanded(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Threat Identified',
                style: TextStyle(
                    color: AppColors.phishing,
                    fontSize: 12,
                    fontWeight: FontWeight.w600)),
            const SizedBox(height: 3),
            Text(threatName,
                style: const TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 14,
                    fontWeight: FontWeight.bold,
                    fontFamily: 'monospace')),
          ],
        ),
      ),
    ]),
  );
}

// ── Action row ────────────────────────────────────────────────────
class _ActionRow extends StatelessWidget {
  final VoidCallback onScanAnother;
  final String? permalink;
  const _ActionRow({required this.onScanAnother, this.permalink});
  @override
  Widget build(BuildContext context) => Row(children: [
    Expanded(
      child: _OutlineButton(
        icon:  Icons.add_circle_outline,
        label: 'Scan Another',
        onTap: onScanAnother,
      ),
    ),
  ]);
}

// ── Shared small widgets ──────────────────────────────────────────
class _OutlineButton extends StatelessWidget {
  final IconData icon;
  final String label;
  final VoidCallback onTap;
  const _OutlineButton({
    required this.icon,
    required this.label,
    required this.onTap,
  });
  @override
  Widget build(BuildContext context) => GestureDetector(
    onTap: onTap,
    child: Container(
      padding: const EdgeInsets.symmetric(vertical: 13),
      decoration: BoxDecoration(
        color: AppColors.vtColor.withOpacity(0.1),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
            color: AppColors.vtColor.withOpacity(0.4)),
      ),
      child: Row(mainAxisAlignment: MainAxisAlignment.center, children: [
        Icon(icon, color: AppColors.vtColor, size: 18),
        const SizedBox(width: 8),
        Text(label,
            style: const TextStyle(
                color: AppColors.vtColor,
                fontSize: 14,
                fontWeight: FontWeight.w600)),
      ]),
    ),
  );
}

class _ErrorCard extends StatelessWidget {
  final String message;
  const _ErrorCard({required this.message});
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.all(14),
    decoration: BoxDecoration(
      color: AppColors.phishing.withOpacity(0.08),
      borderRadius: BorderRadius.circular(12),
      border: Border.all(
          color: AppColors.phishing.withOpacity(0.35)),
    ),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Icon(Icons.error_outline,
            color: AppColors.phishing, size: 20),
        const SizedBox(width: 10),
        Expanded(
          child: Text(message,
              style: const TextStyle(
                  color: AppColors.phishing, fontSize: 13)),
        ),
      ],
    ),
  );
}
