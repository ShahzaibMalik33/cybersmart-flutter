// lib/widgets/shared_widgets.dart

import 'package:flutter/material.dart';
import '../models/scan_result.dart';

// ── Color palette ────────────────────────────────────────────────
abstract class AppColors {
  static const bg          = Color(0xFF0A0F1E);
  static const surface     = Color(0xFF0F172A);
  static const card        = Color(0xFF1A2235);
  static const cardBorder  = Color(0xFF1E2D45);
  static const accent      = Color(0xFF3B82F6);
  static const accentLight = Color(0xFF60A5FA);
  static const safe        = Color(0xFF22C55E);
  static const phishing    = Color(0xFFEF4444);
  static const warning     = Color(0xFFF59E0B);
  static const vtColor     = Color(0xFF8B5CF6);
  static const textPrimary   = Color(0xFFE2E8F0);
  static const textSecondary = Color(0xFF64748B);
  static const textMuted     = Color(0xFF334155);
}

// ── Result Display (big verdict card) ───────────────────────────
class ResultDisplay extends StatelessWidget {
  final ScanResult r;
  const ResultDisplay({super.key, required this.r});

  @override
  Widget build(BuildContext context) {
    final color = r.isPhishing ? AppColors.phishing : AppColors.safe;
    final icon  = r.isPhishing ? Icons.dangerous_outlined : Icons.verified_user_outlined;

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [color.withOpacity(0.12), color.withOpacity(0.04)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: color.withOpacity(0.35), width: 1.5),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(children: [
            Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: color.withOpacity(0.15),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Icon(icon, color: color, size: 28),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    r.isPhishing ? '⚠️ Phishing Detected' : '✅ Safe URL',
                    style: TextStyle(
                      color: color, fontSize: 18, fontWeight: FontWeight.bold),
                  ),
                  Text(
                    r.riskLevel,
                    style: const TextStyle(
                      color: AppColors.textSecondary, fontSize: 13),
                  ),
                ],
              ),
            ),
          ]),
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
            decoration: BoxDecoration(
              color: AppColors.surface,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Text(
              r.url,
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(
                color: AppColors.textSecondary, fontSize: 12,
                fontFamily: 'monospace'),
            ),
          ),
          const SizedBox(height: 14),
          Row(children: [
            _Badge(r.confidence, AppColors.accent),
            const SizedBox(width: 8),
            _Badge(r.method, AppColors.vtColor),
          ]),
        ],
      ),
    );
  }
}

// ── VirusTotal Result Card ───────────────────────────────────────
class VtResultCard extends StatelessWidget {
  final ScanResult r;
  final VoidCallback? onRetry;
  const VtResultCard({super.key, required this.r, this.onRetry});

  @override
  Widget build(BuildContext context) {
    final status = r.vtStatus ?? 'not_checked';

    if (status == 'pending') {
      return _VtShell(
        child: Row(children: const [
          SizedBox(
            width: 18, height: 18,
            child: CircularProgressIndicator(
              color: AppColors.vtColor, strokeWidth: 2.5)),
          SizedBox(width: 12),
          Text('VirusTotal is scanning...',
              style: TextStyle(color: AppColors.textSecondary, fontSize: 13)),
        ]),
      );
    }

    if (status == 'error') {
      return _VtShell(
        child: Row(children: [
          const Icon(Icons.wifi_off_outlined,
              color: AppColors.warning, size: 20),
          const SizedBox(width: 10),
          const Expanded(
            child: Text('VT check failed — requires internet',
                style: TextStyle(color: AppColors.warning, fontSize: 13)),
          ),
          if (onRetry != null)
            GestureDetector(
              onTap: onRetry,
              child: Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                  color: AppColors.warning.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(
                      color: AppColors.warning.withOpacity(0.4)),
                ),
                child: const Text('Retry',
                    style: TextStyle(
                        color: AppColors.warning,
                        fontSize: 12,
                        fontWeight: FontWeight.w600)),
              ),
            ),
        ]),
      );
    }

    if (status == 'not_checked') {
      return _VtShell(
        child: Row(children: [
          const Icon(Icons.shield_outlined,
              color: AppColors.textSecondary, size: 20),
          const SizedBox(width: 10),
          const Text('VirusTotal check not run',
              style: TextStyle(
                  color: AppColors.textSecondary, fontSize: 13)),
        ]),
      );
    }

    // status == 'done'
    final malicious  = r.vtMalicious  ?? 0;
    final suspicious = r.vtSuspicious ?? 0;
    final total      = r.vtTotal      ?? 0;
    final clean      = r.vtClean      ?? 0;
    final flagged    = malicious + suspicious;
    final color      = flagged > 0 ? AppColors.phishing : AppColors.safe;

    return _VtShell(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(children: [
            Icon(flagged > 0 ? Icons.bug_report_outlined : Icons.verified_outlined,
                color: color, size: 20),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                flagged > 0
                    ? '$flagged / $total engines flagged this URL'
                    : 'Clean — $clean / $total engines passed',
                style: TextStyle(
                    color: color,
                    fontSize: 13,
                    fontWeight: FontWeight.w600),
              ),
            ),
          ]),
          const SizedBox(height: 10),
          // Mini stat row
          Row(children: [
            _VtStat('$malicious', 'Malicious', AppColors.phishing),
            const SizedBox(width: 8),
            _VtStat('$suspicious', 'Suspicious', AppColors.warning),
            const SizedBox(width: 8),
            _VtStat('$clean', 'Clean', AppColors.safe),
            const SizedBox(width: 8),
            _VtStat('$total', 'Engines', AppColors.vtColor),
          ]),
          // Progress bar
          const SizedBox(height: 10),
          ClipRRect(
            borderRadius: BorderRadius.circular(4),
            child: LinearProgressIndicator(
              value: total > 0 ? flagged / total : 0,
              backgroundColor: AppColors.safe.withOpacity(0.2),
              valueColor: AlwaysStoppedAnimation(color),
              minHeight: 6,
            ),
          ),
        ],
      ),
    );
  }
}

class _VtShell extends StatelessWidget {
  final Widget child;
  const _VtShell({required this.child});
  @override
  Widget build(BuildContext context) => Container(
        width: double.infinity,
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: AppColors.vtColor.withOpacity(0.06),
          borderRadius: BorderRadius.circular(14),
          border: Border.all(color: AppColors.vtColor.withOpacity(0.25)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(children: [
              const Icon(Icons.biotech_outlined,
                  color: AppColors.vtColor, size: 14),
              const SizedBox(width: 5),
              const Text('VirusTotal API',
                  style: TextStyle(
                      color: AppColors.vtColor,
                      fontSize: 11,
                      fontWeight: FontWeight.w600,
                      letterSpacing: 0.5)),
            ]),
            const SizedBox(height: 8),
            child,
          ],
        ),
      );
}

class _VtStat extends StatelessWidget {
  final String val, label;
  final Color color;
  const _VtStat(this.val, this.label, this.color);
  @override
  Widget build(BuildContext context) => Expanded(
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 6),
          decoration: BoxDecoration(
            color: color.withOpacity(0.08),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: color.withOpacity(0.2)),
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

// ── ScanCard (used in History and Results) ──────────────────────
class ScanCard extends StatelessWidget {
  final ScanResult r;
  const ScanCard({super.key, required this.r});

  @override
  Widget build(BuildContext context) {
    final color = r.isPhishing ? AppColors.phishing : AppColors.safe;
    final icon  = r.isPhishing ? Icons.dangerous_outlined : Icons.check_circle_outline;

    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: AppColors.card,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: color.withOpacity(0.2)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(children: [
            Container(
              padding: const EdgeInsets.all(7),
              decoration: BoxDecoration(
                color: color.withOpacity(0.12),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Icon(icon, color: color, size: 16),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    r.url.length > 45
                        ? '${r.url.substring(0, 45)}...'
                        : r.url,
                    style: const TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 13,
                        fontWeight: FontWeight.w500),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    _formatDate(r.scannedAt),
                    style: const TextStyle(
                        color: AppColors.textSecondary, fontSize: 11),
                  ),
                ],
              ),
            ),
            Column(crossAxisAlignment: CrossAxisAlignment.end, children: [
              Container(
                padding: const EdgeInsets.symmetric(
                    horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: color.withOpacity(0.12),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Text(
                  r.label,
                  style: TextStyle(
                      color: color,
                      fontSize: 11,
                      fontWeight: FontWeight.bold),
                ),
              ),
              const SizedBox(height: 4),
              Text(
                '${(r.probability * 100).toStringAsFixed(0)}%',
                style: TextStyle(color: color, fontSize: 12),
              ),
            ]),
          ]),
          // VT indicator (compact)
          if (r.vtStatus != null && r.vtStatus != 'not_checked') ...[
            const SizedBox(height: 8),
            const Divider(color: AppColors.cardBorder, height: 1),
            const SizedBox(height: 8),
            _VtMiniRow(r: r),
          ],
        ],
      ),
    );
  }

  String _formatDate(DateTime dt) {
    final now = DateTime.now();
    final diff = now.difference(dt);
    if (diff.inMinutes < 1) return 'Just now';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24)   return '${diff.inHours}h ago';
    return '${dt.day}/${dt.month}/${dt.year}';
  }
}

class _VtMiniRow extends StatelessWidget {
  final ScanResult r;
  const _VtMiniRow({required this.r});
  @override
  Widget build(BuildContext context) {
    if (r.vtStatus == 'pending') {
      return Row(children: const [
        SizedBox(
          width: 12, height: 12,
          child: CircularProgressIndicator(
              strokeWidth: 2, color: AppColors.vtColor)),
        SizedBox(width: 6),
        Text('VT scanning...',
            style: TextStyle(color: AppColors.vtColor, fontSize: 11)),
      ]);
    }
    if (r.vtStatus == 'error') {
      return const Row(children: [
        Icon(Icons.wifi_off_outlined, color: AppColors.warning, size: 13),
        SizedBox(width: 5),
        Text('VT offline', style: TextStyle(
            color: AppColors.warning, fontSize: 11)),
      ]);
    }
    final flagged = (r.vtMalicious ?? 0) + (r.vtSuspicious ?? 0);
    final color   = flagged > 0 ? AppColors.phishing : AppColors.safe;
    return Row(children: [
      Icon(Icons.biotech_outlined, color: AppColors.vtColor, size: 13),
      const SizedBox(width: 5),
      Text(
        flagged > 0
            ? 'VT: $flagged/${r.vtTotal} flagged'
            : 'VT: Clean (${r.vtTotal} engines)',
        style: TextStyle(color: color, fontSize: 11,
            fontWeight: FontWeight.w500),
      ),
    ]);
  }
}

// ── Small badge ─────────────────────────────────────────────────
class _Badge extends StatelessWidget {
  final String text;
  final Color color;
  const _Badge(this.text, this.color);
  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 4),
        decoration: BoxDecoration(
          color: color.withOpacity(0.1),
          borderRadius: BorderRadius.circular(6),
          border: Border.all(color: color.withOpacity(0.3)),
        ),
        child: Text(text,
            style: TextStyle(
                color: color, fontSize: 11, fontWeight: FontWeight.w600)),
      );
}
