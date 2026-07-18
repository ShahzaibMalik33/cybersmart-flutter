// lib/screens/text_scanner_screen.dart

import 'package:flutter/material.dart';
import '../services/phishing_detector.dart';
import '../services/virustotal_service.dart';
import '../services/history_service.dart';
import '../models/scan_result.dart';
import '../widgets/shared_widgets.dart';

class TextScannerScreen extends StatefulWidget {
  const TextScannerScreen({super.key});
  @override
  State<TextScannerScreen> createState() => _TextScannerScreenState();
}

class _TextScannerScreenState extends State<TextScannerScreen> {
  final _ctrl = TextEditingController();
  bool             _loading    = false;
  bool             _vtLoading  = false;
  List<ScanResult> _results    = [];
  String?          _error;

  static final _urlRx = RegExp(
    r'https?://[^\s<>"{}|\\^`\[\]]+|'
    r'www\.[a-zA-Z0-9][a-zA-Z0-9\-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}[^\s]*',
    caseSensitive: false,
  );

  List<String> _extractUrls(String text) =>
      _urlRx.allMatches(text).map((m) => m.group(0)!).toList();

  void _scan() async {
    final text = _ctrl.text.trim();
    if (text.isEmpty) return;
    FocusScope.of(context).unfocus();

    final urls = _extractUrls(text);
    if (urls.isEmpty) {
      setState(() => _error =
          'No URL found. Message should contain http:// or www. link.');
      return;
    }

    setState(() { _loading = true; _results = []; _error = null; });

    final results = <ScanResult>[];
    for (final url in urls) {
      final p = PhishingDetector.scan(url);
      final r = ScanResult(
        url:         p['url'],
        label:       p['label'],
        probability: p['probability'],
        confidence:  p['confidence'],
        riskLevel:   p['risk_level'],
        method:      p['method'],
        scannedAt:   DateTime.now(),
        scanType:    'text',
        vtStatus:    'not_checked',
      );
      await HistoryService.add(r);
      results.add(r);
    }

    setState(() { _results = results; _loading = false; });

    // Run VT checks in background for all found URLs
    _runVtForAll(results);
  }

  void _runVtForAll(List<ScanResult> results) async {
    setState(() => _vtLoading = true);

    // Mark all as pending first
    final pending = results.map((r) => r.copyWith(vtStatus: 'pending')).toList();
    setState(() => _results = pending);

    for (int i = 0; i < results.length; i++) {
      final vt = await VirusTotalService.scanUrl(results[i].url);
      final updated = results[i].copyWith(
        vtStatus:     vt['status'],
        vtMalicious:  vt['malicious'],
        vtSuspicious: vt['suspicious'],
        vtClean:      vt['clean'],
        vtTotal:      vt['total'],
        vtPermalink:  vt['permalink'],
      );
      await HistoryService.update(updated);
      if (mounted) {
        setState(() {
          final newList = List<ScanResult>.from(_results);
          newList[i] = updated;
          _results = newList;
        });
      }
    }

    if (mounted) setState(() => _vtLoading = false);
  }

  void _loadSample(String t) { _ctrl.text = t; setState(() {}); }
  void _clear() => setState(() { _ctrl.clear(); _results = []; _error = null; });

  int get _dangerCount => _results.where((r) => r.isPhishing).length;
  int get _vtFlagCount  => _results.where((r) => r.vtFlagged).length;

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

              // Header
              Row(children: [
                Container(
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: AppColors.accent.withOpacity(0.12),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                        color: AppColors.accent.withOpacity(0.3)),
                  ),
                  child: const Icon(Icons.sms_outlined,
                      color: AppColors.accent, size: 22),
                ),
                const SizedBox(width: 12),
                const Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('SMS / Email Scanner',
                        style: TextStyle(
                            color: AppColors.textPrimary,
                            fontSize: 20,
                            fontWeight: FontWeight.bold)),
                    Text('Paste a message and scan all links inside',
                        style: TextStyle(
                            color: AppColors.textSecondary, fontSize: 12)),
                  ],
                ),
              ]),

              const SizedBox(height: 18),

              // Sample chips
              SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                child: Row(children: [
                  _SampleChip('🎁 Prize SMS',
                      'Congratulations! You won Rs 50,000! '
                      'Claim now: http://prize-winner.xyz/claim?id=5523', _loadSample),
                  const SizedBox(width: 8),
                  _SampleChip('🏦 Bank Alert',
                      'URGENT: Your HBL account will be suspended. '
                      'Verify immediately: http://hbl-secure.ml/login', _loadSample),
                  const SizedBox(width: 8),
                  _SampleChip('📦 Package SMS',
                      'Your parcel is held. Update details: '
                      'http://tracking-update.tk/verify', _loadSample),
                  const SizedBox(width: 8),
                  _SampleChip('✅ Safe SMS',
                      'Rs 25,000 credited to your HBL account. '
                      'Balance: Rs 87,340. Ref: TXN20240412.', _loadSample),
                ]),
              ),

              const SizedBox(height: 14),

              // Text input box
              Container(
                decoration: BoxDecoration(
                  color: AppColors.card,
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(
                      color: AppColors.accent.withOpacity(0.25)),
                ),
                child: Column(children: [
                  TextField(
                    controller: _ctrl,
                    maxLines: 6,
                    style: const TextStyle(
                        color: AppColors.textPrimary, fontSize: 13),
                    decoration: const InputDecoration(
                      hintText:
                          'Paste any SMS, WhatsApp message, or email here...',
                      hintStyle: TextStyle(
                          color: AppColors.textSecondary, fontSize: 13),
                      contentPadding: EdgeInsets.all(14),
                      border: InputBorder.none,
                    ),
                    onChanged: (_) => setState(() {}),
                  ),
                  if (_ctrl.text.isNotEmpty) ...[
                    const Divider(
                        color: AppColors.cardBorder, height: 1),
                    Padding(
                      padding: const EdgeInsets.all(10),
                      child: Row(children: [
                        Expanded(
                            child: _OutlineBtn('Clear', Icons.clear, _clear)),
                        const SizedBox(width: 10),
                        Expanded(
                          flex: 2,
                          child: _FilledBtn(
                              'Scan Message',
                              Icons.radar,
                              _loading ? null : _scan),
                        ),
                      ]),
                    ),
                  ],
                ]),
              ),

              const SizedBox(height: 18),

              // Loading
              if (_loading) const Center(
                child: Column(children: [
                  CircularProgressIndicator(color: AppColors.accent),
                  SizedBox(height: 10),
                  Text('Extracting and scanning links...',
                      style: TextStyle(
                          color: AppColors.textSecondary, fontSize: 13)),
                ]),
              ),

              // Error
              if (_error != null) _ErrBox(_error!),

              // Summary banner
              if (_results.isNotEmpty) ...[
                _SummaryBanner(
                  results:       _results,
                  dangerCount:   _dangerCount,
                  vtFlagCount:   _vtFlagCount,
                  vtLoading:     _vtLoading,
                ),
                const SizedBox(height: 12),
                ..._results.asMap().entries.map((e) {
                  final i = e.key;
                  final r = e.value;
                  return Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      ScanCard(r: r),
                      if (r.vtStatus != null)
                        Padding(
                          padding: const EdgeInsets.only(bottom: 8),
                          child: VtResultCard(
                            r: r,
                            onRetry: () async {
                              final vt = await VirusTotalService.scanUrl(r.url);
                              final updated = r.copyWith(
                                vtStatus:     vt['status'],
                                vtMalicious:  vt['malicious'],
                                vtSuspicious: vt['suspicious'],
                                vtClean:      vt['clean'],
                                vtTotal:      vt['total'],
                              );
                              if (mounted) setState(() => _results[i] = updated);
                            },
                          ),
                        ),
                    ],
                  );
                }),
              ],
            ],
          ),
        ),
      ),
    );
  }
}

// ── Summary banner ───────────────────────────────────────────────
class _SummaryBanner extends StatelessWidget {
  final List<ScanResult> results;
  final int dangerCount, vtFlagCount;
  final bool vtLoading;
  const _SummaryBanner({
    required this.results,
    required this.dangerCount,
    required this.vtFlagCount,
    required this.vtLoading,
  });

  @override
  Widget build(BuildContext context) {
    final aiDanger = dangerCount > 0;
    final vtDanger = vtFlagCount > 0;
    final anyDanger = aiDanger || vtDanger;
    final color = anyDanger ? AppColors.phishing : AppColors.safe;

    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: color.withOpacity(0.08),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: color.withOpacity(0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(children: [
            Icon(anyDanger ? Icons.dangerous_outlined : Icons.check_circle_outline,
                color: color, size: 24),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    anyDanger
                        ? '⚠️ Dangerous links detected!'
                        : '✅ All links are safe',
                    style: TextStyle(
                        color: color,
                        fontSize: 14,
                        fontWeight: FontWeight.bold),
                  ),
                  Text('${results.length} link${results.length > 1 ? 's' : ''} scanned',
                      style: const TextStyle(
                          color: AppColors.textSecondary, fontSize: 11)),
                ],
              ),
            ),
          ]),
          const SizedBox(height: 10),
          Row(children: [
            _MiniStat('${results.length}', 'Total', AppColors.accent),
            const SizedBox(width: 6),
            _MiniStat('$dangerCount', 'AI Phish', AppColors.phishing),
            const SizedBox(width: 6),
            if (vtLoading)
              _MiniStat('...', 'VT Check', AppColors.vtColor)
            else
              _MiniStat('$vtFlagCount', 'VT Flagged', AppColors.vtColor),
          ]),
        ],
      ),
    );
  }
}

class _MiniStat extends StatelessWidget {
  final String val, label;
  final Color color;
  const _MiniStat(this.val, this.label, this.color);
  @override
  Widget build(BuildContext context) => Expanded(
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 6),
          decoration: BoxDecoration(
            color: color.withOpacity(0.1),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Column(children: [
            Text(val,
                style: TextStyle(
                    color: color,
                    fontSize: 15,
                    fontWeight: FontWeight.bold)),
            Text(label,
                style: const TextStyle(
                    color: AppColors.textSecondary, fontSize: 10)),
          ]),
        ),
      );
}

// ── Helpers ──────────────────────────────────────────────────────
class _SampleChip extends StatelessWidget {
  final String label, text;
  final void Function(String) onTap;
  const _SampleChip(this.label, this.text, this.onTap);
  @override
  Widget build(BuildContext context) => GestureDetector(
        onTap: () => onTap(text),
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          decoration: BoxDecoration(
            color: AppColors.card,
            borderRadius: BorderRadius.circular(20),
            border: Border.all(color: AppColors.accent.withOpacity(0.3)),
          ),
          child: Text(label,
              style: const TextStyle(
                  color: AppColors.accent, fontSize: 12)),
        ),
      );
}

class _OutlineBtn extends StatelessWidget {
  final String label;
  final IconData icon;
  final VoidCallback? onTap;
  const _OutlineBtn(this.label, this.icon, this.onTap);
  @override
  Widget build(BuildContext context) => GestureDetector(
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 10),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(8),
            border: Border.all(
                color: AppColors.textSecondary.withOpacity(0.3)),
          ),
          child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
            Icon(icon, color: AppColors.textSecondary, size: 15),
            const SizedBox(width: 5),
            Text(label,
                style: const TextStyle(
                    color: AppColors.textSecondary, fontSize: 13)),
          ]),
        ),
      );
}

class _FilledBtn extends StatelessWidget {
  final String label;
  final IconData icon;
  final VoidCallback? onTap;
  const _FilledBtn(this.label, this.icon, this.onTap);
  @override
  Widget build(BuildContext context) => GestureDetector(
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 10),
          decoration: BoxDecoration(
            color: AppColors.accent.withOpacity(0.15),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(
                color: AppColors.accent.withOpacity(0.4)),
          ),
          child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
            Icon(icon, color: AppColors.accent, size: 15),
            const SizedBox(width: 5),
            Text(label,
                style: const TextStyle(
                    color: AppColors.accent,
                    fontSize: 13,
                    fontWeight: FontWeight.w600)),
          ]),
        ),
      );
}

class _ErrBox extends StatelessWidget {
  final String msg;
  const _ErrBox(this.msg);
  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: AppColors.warning.withOpacity(0.1),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(
              color: AppColors.warning.withOpacity(0.3)),
        ),
        child: Row(children: [
          const Icon(Icons.info_outline,
              color: AppColors.warning, size: 18),
          const SizedBox(width: 8),
          Expanded(
              child: Text(msg,
                  style: const TextStyle(
                      color: AppColors.warning, fontSize: 12))),
        ]),
      );
}
