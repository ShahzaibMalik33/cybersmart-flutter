// lib/screens/scanner_screen.dart

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../services/phishing_detector.dart';
import '../services/virustotal_service.dart';
import '../services/history_service.dart';
import '../models/scan_result.dart';
import '../widgets/shared_widgets.dart';

class ScannerScreen extends StatefulWidget {
  const ScannerScreen({super.key});
  @override
  State<ScannerScreen> createState() => _ScannerScreenState();
}

class _ScannerScreenState extends State<ScannerScreen>
    with SingleTickerProviderStateMixin {
  final _ctrl      = TextEditingController();
  final _focusNode = FocusNode();
  bool        _loading   = false;
  bool        _vtLoading = false;
  ScanResult? _result;
  String?     _error;
  String?     _inputWarning; // shown when input is not a URL

  late AnimationController _pulse;
  late Animation<double>   _anim;

  @override
  void initState() {
    super.initState();
    _pulse = AnimationController(
        vsync: this, duration: const Duration(seconds: 2))
      ..repeat(reverse: true);
    _anim = Tween(begin: 0.88, end: 1.0).animate(
        CurvedAnimation(parent: _pulse, curve: Curves.easeInOut));
  }

  @override
  void dispose() {
    _ctrl.dispose();
    _focusNode.dispose();
    _pulse.dispose();
    super.dispose();
  }

  // ── Validate input before scanning ───────────────────────────
  void _scan() async {
    final raw = _ctrl.text.trim();
    if (raw.isEmpty) return;
    _focusNode.unfocus();

    // ── VALIDATION: Reject plain text ──
    if (!PhishingDetector.isValidUrl(raw)) {
      setState(() {
        _inputWarning = null;
        _error  = null;
        _result = null;
        _loading = false;
      });
      // Show inline warning — not a scan result
      setState(() => _inputWarning =
          '⚠️  This looks like plain text, not a URL.\n'
          'Please enter a web address like:\n'
          'https://example.com  or  www.example.com');
      return;
    }

    setState(() {
      _loading      = true;
      _result       = null;
      _error        = null;
      _inputWarning = null;
    });

    try {
      final p = PhishingDetector.scan(raw);
      final r = ScanResult(
        url:         p['url'],
        label:       p['label'],
        probability: p['probability'],
        confidence:  p['confidence'],
        riskLevel:   p['risk_level'],
        method:      p['method'],
        scannedAt:   DateTime.now(),
        vtStatus:    'not_checked',
      );
      await HistoryService.add(r);
      setState(() { _result = r; _loading = false; });
      _runVt(r);
    } catch (e) {
      setState(() {
        _error   = 'Scan error: $e';
        _loading = false;
      });
    }
  }

  // ── VirusTotal check ─────────────────────────────────────────
  void _runVt(ScanResult base) async {
    setState(() {
      _vtLoading = true;
      _result    = base.copyWith(vtStatus: 'pending');
    });

    final vt = await VirusTotalService.scanUrl(base.url);

    final updated = base.copyWith(
      vtStatus:     vt['status'],
      vtMalicious:  vt['malicious'],
      vtSuspicious: vt['suspicious'],
      vtClean:      vt['clean'],
      vtTotal:      vt['total'],
      vtPermalink:  vt['permalink'],
    );

    await HistoryService.update(updated);
    if (mounted) setState(() { _result = updated; _vtLoading = false; });
  }

  void _paste() async {
    final d = await Clipboard.getData(Clipboard.kTextPlain);
    if (d?.text != null && d!.text!.trim().isNotEmpty) {
      _ctrl.text = d.text!.trim();
      setState(() {});
      _scan();
    }
  }

  void _clear() => setState(() {
    _ctrl.clear();
    _result       = null;
    _error        = null;
    _inputWarning = null;
  });

  @override
  Widget build(BuildContext context) {
    final modelReady = PhishingDetector.isReady;

    return Scaffold(
      backgroundColor: AppColors.bg,
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SizedBox(height: 8),

              // ── Header ──────────────────────────────────────
              Row(children: [
                AnimatedBuilder(
                  animation: _anim,
                  builder: (_, child) =>
                      Transform.scale(scale: _anim.value, child: child),
                  child: Container(
                    width: 52, height: 52,
                    decoration: BoxDecoration(
                      gradient: const LinearGradient(
                          colors: [AppColors.accent, Color(0xFF6366F1)]),
                      borderRadius: BorderRadius.circular(14),
                      boxShadow: [BoxShadow(
                          color: AppColors.accent.withOpacity(0.35),
                          blurRadius: 14, offset: const Offset(0, 4))],
                    ),
                    child: const Icon(Icons.shield_outlined,
                        color: Colors.white, size: 28),
                  ),
                ),
                const SizedBox(width: 14),
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('CyberSmart',
                        style: TextStyle(
                            color: AppColors.textPrimary,
                            fontSize: 22,
                            fontWeight: FontWeight.bold)),
                    Row(children: [
                      _StatusDot(active: modelReady,
                          activeColor: AppColors.safe,
                          inactiveColor: AppColors.warning),
                      const SizedBox(width: 5),
                      Text(modelReady ? 'AI Model Ready' : 'Loading...',
                          style: TextStyle(
                              color: modelReady
                                  ? AppColors.safe : AppColors.warning,
                              fontSize: 12)),
                      const SizedBox(width: 10),
                      _StatusDot(active: true,
                          activeColor: AppColors.vtColor),
                      const SizedBox(width: 5),
                      const Text('VT API Active',
                          style: TextStyle(
                              color: AppColors.vtColor, fontSize: 12)),
                    ]),
                  ],
                ),
              ]),

              const SizedBox(height: 20),

              // ── Status pills ────────────────────────────────
              Row(children: [
                _Pill(Icons.offline_bolt_outlined, 'On-Device AI', AppColors.safe),
                const SizedBox(width: 8),
                _Pill(Icons.biotech_outlined, 'VirusTotal', AppColors.vtColor),
                const SizedBox(width: 8),
                _Pill(Icons.lock_outline, 'Private', AppColors.accent),
              ]),

              const SizedBox(height: 18),

              // ── Input card ──────────────────────────────────
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: AppColors.card,
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(
                    color: _inputWarning != null
                        ? AppColors.warning.withOpacity(0.5)
                        : AppColors.accent.withOpacity(0.3)),
                  boxShadow: [BoxShadow(
                      color: Colors.black.withOpacity(0.3),
                      blurRadius: 12, offset: const Offset(0, 4))],
                ),
                child: Column(children: [
                  TextField(
                    controller: _ctrl,
                    focusNode:  _focusNode,
                    style: const TextStyle(
                        color: AppColors.textPrimary, fontSize: 14),
                    decoration: InputDecoration(
                      hintText:  'Enter URL: https://example.com',
                      hintStyle: const TextStyle(
                          color: AppColors.textSecondary),
                      prefixIcon: const Icon(Icons.link,
                          color: AppColors.accent, size: 20),
                      suffixIcon: _ctrl.text.isNotEmpty
                          ? IconButton(
                              icon: const Icon(Icons.clear,
                                  color: AppColors.textSecondary, size: 18),
                              onPressed: _clear)
                          : null,
                      border: InputBorder.none,
                    ),
                    onSubmitted: (_) => _scan(),
                    onChanged:   (_) => setState(() {
                      _inputWarning = null; // clear warning as user types
                    }),
                  ),
                  const Divider(color: AppColors.cardBorder, height: 1),
                  const SizedBox(height: 10),
                  Row(children: [
                    Expanded(child: _ActionBtn(
                      icon: Icons.content_paste_outlined,
                      label: 'Paste',
                      color: AppColors.textSecondary,
                      onTap: _paste,
                    )),
                    const SizedBox(width: 10),
                    Expanded(flex: 2, child: _ActionBtn(
                      icon:   _loading ? Icons.hourglass_empty : Icons.radar,
                      label:  _loading ? 'Scanning...' : 'Scan URL',
                      color:  AppColors.accent,
                      filled: true,
                      onTap:  _loading || !modelReady ? null : _scan,
                    )),
                  ]),
                ]),
              ),

              const SizedBox(height: 16),

              // ── Input warning (plain text entered) ──────────
              if (_inputWarning != null) _InputWarningBox(_inputWarning!),

              // ── Loading ─────────────────────────────────────
              if (_loading) const Center(
                child: Column(children: [
                  SizedBox(height: 20),
                  SizedBox(
                    width: 48, height: 48,
                    child: CircularProgressIndicator(
                        color: AppColors.accent, strokeWidth: 3)),
                  SizedBox(height: 14),
                  Text('AI analyzing URL...',
                      style: TextStyle(
                          color: AppColors.textPrimary, fontSize: 15,
                          fontWeight: FontWeight.w500)),
                  SizedBox(height: 4),
                  Text('On-device — no internet required for AI',
                      style: TextStyle(
                          color: AppColors.textSecondary, fontSize: 12)),
                ]),
              ),

              // ── Error ───────────────────────────────────────
              if (_error != null) _ErrorBox(_error!),

              // ── Results ─────────────────────────────────────
              if (_result != null) ...[
                ResultDisplay(r: _result!),
                const SizedBox(height: 12),
                _ProbabilityBar(r: _result!),
                const SizedBox(height: 12),
                VtResultCard(
                  r: _result!,
                  onRetry: _vtLoading ? null : () => _runVt(_result!),
                ),
              ],

              // ── Empty hints ─────────────────────────────────
              if (!_loading && _result == null &&
                  _error == null && _inputWarning == null) ...[
                const SizedBox(height: 28),
                _InfoCard(
                  icon: Icons.psychology_outlined,
                  title: 'Dual-Engine Protection',
                  body: 'On-device AI + VirusTotal 90+ engines work together',
                  color: AppColors.accent,
                ),
                const SizedBox(height: 10),
                _InfoCard(
                  icon: Icons.link,
                  title: 'URLs Only',
                  body: 'Enter a web link like https://example.com or www.site.com',
                  color: AppColors.warning,
                ),
                const SizedBox(height: 10),
                _InfoCard(
                  icon: Icons.offline_bolt_outlined,
                  title: 'Works Offline',
                  body: 'AI model runs fully on-device, no internet needed',
                  color: AppColors.safe,
                ),
                const SizedBox(height: 10),
                _InfoCard(
                  icon: Icons.biotech_outlined,
                  title: 'VirusTotal Cross-Check',
                  body: '90+ antivirus engines verify when internet is available',
                  color: AppColors.vtColor,
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }
}

// ── Input Warning Box ─────────────────────────────────────────────
class _InputWarningBox extends StatelessWidget {
  final String message;
  const _InputWarningBox(this.message);
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.all(14),
    decoration: BoxDecoration(
      color: AppColors.warning.withOpacity(0.1),
      borderRadius: BorderRadius.circular(12),
      border: Border.all(color: AppColors.warning.withOpacity(0.4)),
    ),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Icon(Icons.info_outline, color: AppColors.warning, size: 22),
        const SizedBox(width: 10),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('Not a URL',
                  style: TextStyle(
                      color: AppColors.warning,
                      fontSize: 14,
                      fontWeight: FontWeight.bold)),
              const SizedBox(height: 4),
              Text(message,
                  style: const TextStyle(
                      color: AppColors.textSecondary, fontSize: 13)),
            ],
          ),
        ),
      ],
    ),
  );
}

// ── Shared sub-widgets ────────────────────────────────────────────
class _StatusDot extends StatelessWidget {
  final bool active;
  final Color activeColor;
  final Color inactiveColor;
  const _StatusDot({
    required this.active,
    required this.activeColor,
    this.inactiveColor = AppColors.warning,
  });
  @override
  Widget build(BuildContext context) {
    final color = active ? activeColor : inactiveColor;
    return Container(
      width: 7, height: 7,
      decoration: BoxDecoration(
        shape: BoxShape.circle, color: color,
        boxShadow: [BoxShadow(
            color: color.withOpacity(0.6), blurRadius: 4, spreadRadius: 1)],
      ),
    );
  }
}

class _Pill extends StatelessWidget {
  final IconData icon;
  final String label;
  final Color color;
  const _Pill(this.icon, this.label, this.color);
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
    decoration: BoxDecoration(
      color: color.withOpacity(0.1),
      borderRadius: BorderRadius.circular(20),
      border: Border.all(color: color.withOpacity(0.3)),
    ),
    child: Row(mainAxisSize: MainAxisSize.min, children: [
      Icon(icon, color: color, size: 13),
      const SizedBox(width: 5),
      Text(label,
          style: TextStyle(
              color: color, fontSize: 11, fontWeight: FontWeight.w600)),
    ]),
  );
}

class _ActionBtn extends StatelessWidget {
  final IconData icon;
  final String label;
  final Color color;
  final VoidCallback? onTap;
  final bool filled;
  const _ActionBtn({
    required this.icon,
    required this.label,
    required this.color,
    this.onTap,
    this.filled = false,
  });
  @override
  Widget build(BuildContext context) => GestureDetector(
    onTap: onTap,
    child: AnimatedOpacity(
      opacity: onTap == null ? 0.5 : 1.0,
      duration: const Duration(milliseconds: 200),
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 11),
        decoration: BoxDecoration(
          color: filled ? color.withOpacity(0.15) : Colors.transparent,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(
              color: color.withOpacity(filled ? 0.45 : 0.2)),
        ),
        child: Row(mainAxisAlignment: MainAxisAlignment.center, children: [
          Icon(icon, color: color, size: 16),
          const SizedBox(width: 6),
          Text(label,
              style: TextStyle(
                  color: color, fontSize: 13, fontWeight: FontWeight.w600)),
        ]),
      ),
    ),
  );
}

class _ProbabilityBar extends StatelessWidget {
  final ScanResult r;
  const _ProbabilityBar({required this.r});
  @override
  Widget build(BuildContext context) {
    final prob  = r.probability;
    final pct   = (prob * 100).toStringAsFixed(1);
    final color = r.isPhishing ? AppColors.phishing : AppColors.safe;
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: AppColors.card,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: AppColors.cardBorder),
      ),
      child: Column(children: [
        Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
          const Text('Phishing Probability',
              style: TextStyle(
                  color: AppColors.textSecondary, fontSize: 13)),
          Text('$pct%',
              style: TextStyle(
                  color: color, fontSize: 14, fontWeight: FontWeight.bold)),
        ]),
        const SizedBox(height: 10),
        ClipRRect(
          borderRadius: BorderRadius.circular(4),
          child: LinearProgressIndicator(
            value: prob,
            backgroundColor: AppColors.safe.withOpacity(0.2),
            valueColor: AlwaysStoppedAnimation(color),
            minHeight: 8,
          ),
        ),
        const SizedBox(height: 8),
        const Row(mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
          Text('Safe', style: TextStyle(color: AppColors.safe, fontSize: 11)),
          Text('Phishing',
              style: TextStyle(color: AppColors.phishing, fontSize: 11)),
        ]),
      ]),
    );
  }
}

class _InfoCard extends StatelessWidget {
  final IconData icon;
  final String title, body;
  final Color color;
  const _InfoCard({
    required this.icon,
    required this.title,
    required this.body,
    required this.color,
  });
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.all(14),
    decoration: BoxDecoration(
      color: AppColors.card,
      borderRadius: BorderRadius.circular(12),
      border: Border.all(color: color.withOpacity(0.15)),
    ),
    child: Row(children: [
      Container(
        padding: const EdgeInsets.all(9),
        decoration: BoxDecoration(
          color: color.withOpacity(0.1),
          borderRadius: BorderRadius.circular(9),
        ),
        child: Icon(icon, color: color, size: 18),
      ),
      const SizedBox(width: 13),
      Expanded(child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title, style: const TextStyle(
              color: AppColors.textPrimary,
              fontSize: 13, fontWeight: FontWeight.w600)),
          const SizedBox(height: 2),
          Text(body, style: const TextStyle(
              color: AppColors.textSecondary, fontSize: 12)),
        ],
      )),
    ]),
  );
}

class _ErrorBox extends StatelessWidget {
  final String msg;
  const _ErrorBox(this.msg);
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.all(14),
    decoration: BoxDecoration(
      color: AppColors.phishing.withOpacity(0.1),
      borderRadius: BorderRadius.circular(12),
      border: Border.all(color: AppColors.phishing.withOpacity(0.3)),
    ),
    child: Row(children: [
      const Icon(Icons.error_outline, color: AppColors.phishing, size: 20),
      const SizedBox(width: 10),
      Expanded(child: Text(msg,
          style: const TextStyle(
              color: AppColors.phishing, fontSize: 13))),
    ]),
  );
}
