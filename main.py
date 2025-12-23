#!/usr/bin/env python3
"""
ANDROID SECURITY TOOLKIT v2.0 - LEGAL NOTICE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AUTHORIZED USE ONLY. PROHIBITED: Unauthorized access, spying, data theft.
REQUIRES: Device ownership OR written permission. VIOLATION: 5 years imprisonment.
--consent flag mandatory. All actions logged to loot/audit.log.
BY USING THIS TOOL, YOU ACCEPT FULL LEGAL RESPONSIBILITY.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import click
import logging
import sys
import time
from pathlib import Path
from typing import Optional

from modules.adb_security_scanner import ADBSecurityScanner
from modules.adb_data_extractor import ADBDataExtractor
from modules.apk_analyzer import APKAnalyzer
from modules.android_password_cracker import AndroidPasswordCracker
from modules.adb_reverse_shell import ADBReverseShell
from modules.device_monitor import DeviceMonitor
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.frida_integration import FridaIntegration


# ASCII Art Banner
BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    ANDROID SECURITY TOOLKIT v2.0                              ║
║                         LEGAL NOTICE - READ CAREFULLY                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ AUTHORIZED USE ONLY. PROHIBITED: Unauthorized access, spying, data theft.   ║
║ REQUIRES: Device ownership OR written permission. VIOLATION: 5 years prison.  ║
║ --consent flag MANDATORY. All actions logged to loot/audit.log.              ║
║ BY USING THIS TOOL, YOU ACCEPT FULL LEGAL RESPONSIBILITY.                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

💪 POWERFUL ANDROID SECURITY TESTING TOOLKIT
🔒 LEGAL USE ONLY - UNAUTHORIZED ACCESS PROHIBITED
📊 COMPREHENSIVE SECURITY ASSESSMENT PLATFORM
"""


@click.group()
@click.option('--device-id', help='Target device ID')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--consent', is_flag=True, help='Confirm authorized use (REQUIRED)')
@click.pass_context
def cli(ctx, device_id, verbose, consent):
    """Android Security Toolkit - Comprehensive Android security testing platform."""
    
    # Print banner
    click.echo(BANNER)
    
    # Check consent
    if not consent:
        click.echo("\n❌ CRITICAL: --consent flag required for legal compliance")
        click.echo("You MUST have device ownership or written permission")
        click.echo("Unauthorized access is ILLEGAL and punishable by law")
        sys.exit(1)
    
    # Setup logging
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='[%(asctime)s] %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Store context
    ctx.ensure_object(dict)
    ctx.obj['device_id'] = device_id
    ctx.obj['verbose'] = verbose
    ctx.obj['consent'] = consent


@cli.command()
@click.option('--tcp-scan', is_flag=True, help='Scan TCP/IP devices')
@click.option('--output', '-o', help='Output file for results')
@click.pass_context
def adb_discover(ctx, tcp_scan, output):
    """Discover and analyze ADB-connected devices."""
    click.echo("🔍 Starting ADB device discovery...")
    
    scanner = ADBSecurityScanner(device_id=ctx.obj.get('device_id'))
    
    if tcp_scan:
        click.echo("   📡 Scanning TCP/IP network for ADB devices...")
    
    results = scanner.scan()
    
    # Display results
    click.echo(f"\n📊 Discovery Results:")
    click.echo(f"   Total devices found: {results.get('devices_scanned', 0)}")
    click.echo(f"   USB devices: {results.get('metrics', {}).get('devices_scanned', 0)}")
    click.echo(f"   Findings: {results.get('findings_count', 0)}")
    
    for finding in results.get('findings', []):
        severity_color = {
            'CRITICAL': '🔴',
            'HIGH': '🟠', 
            'MEDIUM': '🟡',
            'LOW': '🔵',
            'INFO': 'ℹ️'
        }.get(finding['severity'], '⚪')
        
        click.echo(f"   {severity_color} [{finding['severity']}] {finding['title']}")
    
    if output:
        scanner.export_findings("json", output)
        click.echo(f"\n💾 Results saved to: {output}")


@cli.command()
@click.option('--all-data', is_flag=True, help='Extract all available data')
@click.option('--sms', is_flag=True, help='Extract SMS messages')
@click.option('--contacts', is_flag=True, help='Extract contacts')
@click.option('--call-logs', is_flag=True, help='Extract call logs')
@click.option('--wifi', is_flag=True, help='Extract WiFi passwords')
@click.option('--browser-history', is_flag=True, help='Extract browser history')
@click.option('--output-dir', default='loot/extracted_data', help='Output directory')
@click.pass_context
def extract(ctx, all_data, sms, contacts, call_logs, wifi, browser_history, output_dir):
    """Extract data from Android device."""
    click.echo("📱 Starting data extraction...")
    
    extractor = ADBDataExtractor(device_id=ctx.obj.get('device_id'), output_dir=output_dir)
    
    if all_data:
        click.echo("   📊 Extracting all available data types...")
        results = extractor.extract_all()
    else:
        # Extract specific data types
        results = {}
        
        if sms:
            click.echo("   💬 Extracting SMS messages...")
            results['sms'] = extractor.extract_sms()
        
        if contacts:
            click.echo("   👥 Extracting contacts...")
            results['contacts'] = extractor.extract_contacts()
        
        if call_logs:
            click.echo("   📞 Extracting call logs...")
            results['call_logs'] = extractor.extract_call_logs()
        
        if wifi:
            click.echo("   📶 Extracting WiFi passwords...")
            results['wifi'] = extractor.extract_wifi_passwords()
        
        if browser_history:
            click.echo("   🌐 Extracting browser history...")
            results['browser_history'] = extractor.extract_browser_history()
    
    click.echo("\n✅ Data extraction completed")
    click.echo(f"   Output directory: {output_dir}")


@cli.command()
@click.argument('apk_path')
@click.option('--output', '-o', help='Analysis report output file')
@click.pass_context
def analyze_apk(ctx, apk_path, output):
    """Analyze APK file for security vulnerabilities."""
    click.echo(f"📦 Analyzing APK: {apk_path}")
    
    analyzer = APKAnalyzer()
    results = analyzer.analyze(apk_path)
    
    click.echo(f"\n📊 APK Analysis Results:")
    click.echo(f"   Package: {results.get('manifest', {}).get('package_name', 'Unknown')}")
    click.echo(f"   Risk Score: {results.get('risk_assessment', {}).get('score', 'N/A')}/10")
    click.echo(f"   Permissions: {results.get('manifest', {}).get('permissions', [])}")
    
    # Show critical findings
    for finding in results.get('findings', []):
        if finding['severity'] in ['CRITICAL', 'HIGH']:
            click.echo(f"   🚨 {finding['severity']}: {finding['title']}")
    
    if output:
        analyzer.export_findings("json", output)
        click.echo(f"\n💾 Analysis report saved to: {output}")


@cli.command()
@click.option('--attack-type', type=click.Choice(['pin', 'pattern', 'password']), 
              required=True, help='Type of attack')
@click.option('--min-length', default=4, help='Minimum PIN/password length')
@click.option('--max-length', default=8, help='Maximum PIN/password length')
@click.option('--wordlist', help='Wordlist file for password attacks')
@click.option('--threads', default=8, help='Number of cracking threads')
@click.option('--resume', is_flag=True, help='Resume previous attack')
@click.pass_context
def crack(ctx, attack_type, min_length, max_length, wordlist, threads, resume):
    """Crack Android PINs, patterns, or passwords."""
    click.echo(f"🔓 Starting {attack_type} cracking attack...")
    
    cracker = AndroidPasswordCracker(
        device_id=ctx.obj.get('device_id'),
        threads=threads
    )
    
    if attack_type == 'pin':
        click.echo(f"   🔢 Cracking PINs (length {min_length}-{max_length})...")
        result = cracker.crack_device_pin(min_length, max_length)
        
    elif attack_type == 'pattern':
        click.echo("   📱 Cracking lock patterns...")
        result = cracker.crack_device_pattern()
        
    elif attack_type == 'password':
        click.echo("   🔑 Cracking passwords...")
        wordlist_files = [wordlist] if wordlist else None
        result = cracker.crack_device_password(wordlist_files)
    
    if result:
        click.echo(f"\n🎉 SUCCESS! Cracked: {result}")
        click.echo("   ⚠️  This demonstrates weak security - change immediately!")
    else:
        click.echo("\n❌ Attack failed - target may be secure")


@cli.command()
@click.pass_context
def shell(ctx):
    """Start interactive ADB shell."""
    click.echo("🖥️  Starting interactive ADB shell...")
    
    shell = ADBReverseShell(device_id=ctx.obj.get('device_id'))
    shell.interactive_shell()


@cli.command()
@click.option('--duration', default=60, help='Monitoring duration (seconds)')
@click.option('--webhook', help='Webhook URL for alerts')
@click.pass_context
def monitor(ctx, duration, webhook):
    """Monitor device for suspicious activities."""
    click.echo("👁️  Starting device monitoring...")
    
    monitor = DeviceMonitor(
        device_id=ctx.obj.get('device_id'),
        webhook_url=webhook
    )
    
    monitor.start_monitoring()
    
    click.echo(f"   📡 Monitoring active for {duration} seconds...")
    
    try:
        for remaining in range(duration, 0, -1):
            click.echo(f"   ⏱️  {remaining}s remaining", nl=False)
            time.sleep(1)
            click.echo('\r', nl=False)
        
        monitor.stop_monitoring()
        click.echo("\n✅ Monitoring completed")
        
        stats = monitor.get_monitoring_stats()
        click.echo(f"   📊 Activity log entries: {stats['activity_log_entries']}")
        
    except KeyboardInterrupt:
        monitor.stop_monitoring()
        click.echo("\n🛑 Monitoring stopped by user")


@cli.command()
@click.pass_context
def full_audit(ctx):
    """Perform comprehensive security audit."""
    click.echo("🔍 Starting comprehensive security audit...")
    click.echo("   This will perform all available security checks")
    click.echo()
    
    device_id = ctx.obj.get('device_id')
    
    # Phase 1: Device discovery
    click.echo("📱 Phase 1: Device Discovery")
    scanner = ADBSecurityScanner(device_id=device_id)
    discovery_results = scanner.scan()
    
    # Phase 2: Vulnerability scan
    click.echo("🛡️  Phase 2: Vulnerability Scan")
    vuln_scanner = VulnerabilityScanner(device_id=device_id)
    vuln_results = vuln_scanner.scan()
    
    # Phase 3: Data extraction (if authorized)
    click.echo("📊 Phase 3: Data Extraction")
    extractor = ADBDataExtractor(device_id=device_id)
    extraction_results = extractor.extract_all()
    
    # Phase 4: Generate report
    click.echo("📝 Phase 4: Generating Audit Report")
    audit_report = {
        "timestamp": time.time(),
        "device_id": device_id,
        "discovery_results": discovery_results,
        "vulnerability_results": vuln_results,
        "extraction_summary": extraction_results,
        "audit_summary": {
            "total_findings": len(discovery_results.get('findings', [])) + len(vuln_results.get('findings', [])),
            "critical_issues": discovery_results.get('metrics', {}).get('critical_count', 0) + vuln_results.get('metrics', {}).get('critical_count', 0),
            "high_issues": discovery_results.get('metrics', {}).get('high_count', 0) + vuln_results.get('metrics', {}).get('high_count', 0),
            "recommendations": [
                "Update to latest Android security patch",
                "Review and minimize app permissions",
                "Disable unnecessary ADB access",
                "Implement device encryption",
                "Regular security assessments"
            ]
        }
    }
    
    # Save audit report
    report_file = f"loot/audit_report_{device_id or 'unknown'}_{int(time.time())}.json"
    Path(report_file).parent.mkdir(parents=True, exist_ok=True)
    
    with open(report_file, 'w') as f:
        json.dump(audit_report, f, indent=2, default=str)
    
    click.echo(f"\n✅ Full audit completed!")
    click.echo(f"   📄 Report saved: {report_file}")
    click.echo(f"   🔍 Total findings: {audit_report['audit_summary']['total_findings']}")
    click.echo(f"   ⚠️  Critical issues: {audit_report['audit_summary']['critical_issues']}")
    click.echo(f"   🚨 High issues: {audit_report['audit_summary']['high_issues']}")


@cli.command()
@click.pass_context
def version(ctx):
    """Show toolkit version information."""
    click.echo("""
Android Security Toolkit v2.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔧 Features:
   • ADB Security Scanning
   • Data Extraction & Analysis
   • APK Vulnerability Analysis
   • Password/PIN/Pattern Cracking
   • Interactive Shell Access
   • Real-time Device Monitoring
   • Vulnerability Assessment
   • Dynamic Analysis (Frida)

⚖️  Legal Notice:
   This tool is for AUTHORIZED USE ONLY
   Requires device ownership or written permission
   Violation may result in criminal prosecution

💪 Stay ethical, stay legal, stay powerful!
""")


if __name__ == '__main__':
    cli()