import { spawnSync } from 'node:child_process';
import path from 'node:path';
import type { Confirmer } from '../core/context.ts';

// PLAN.md §6.4. Only prompts the calling agent cannot answer for itself:
//   1) Windows Hello (secure UI: PIN / biometrics)
//   2) fallback: a UAC consent prompt on the secure desktop (UIPI blocks input from medium-integrity processes)
// Anything weaker (console codes, ordinary dialogs) is refused rather than used.
// NOTE: not yet exercised interactively — GUI prompts need CEO approval to test (PLAN.md §5.1 spike 5).

const PS = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
const REG = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'reg.exe');

function ps(script: string, timeoutMs: number): { status: number | null; stdout: string } {
  const r = spawnSync(PS, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], { encoding: 'utf8', windowsHide: false, timeout: timeoutMs });
  return { status: r.status, stdout: (r.stdout ?? '').trim() };
}

const WINRT_PRELUDE = `
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null = [Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType = WindowsRuntime]
$asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation\`1' })[0]
function Await($op, $type) { $t = $asTask.MakeGenericMethod($type).Invoke($null, @($op)); $t.Wait(120000) | Out-Null; $t.Result }
`;

export function helloAvailable(): boolean {
  const r = ps(`${WINRT_PRELUDE}
Await ([Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()) ([Windows.Security.Credentials.UI.UserConsentVerifierAvailability])`, 15_000);
  return r.status === 0 && r.stdout === 'Available';
}

function regDword(key: string, name: string): number | undefined {
  const r = spawnSync(REG, ['query', key, '/v', name], { encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
  const m = /REG_DWORD\s+0x([0-9a-f]+)/i.exec(r.stdout ?? '');
  return m ? parseInt(m[1]!, 16) : undefined;
}

/** UAC is a real gate only if it is on, prompts (consent or credentials), and uses the secure desktop. */
export function uacIsSecureGate(): boolean {
  const k = 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System';
  const lua = regDword(k, 'EnableLUA');
  const admin = regDword(k, 'ConsentPromptBehaviorAdmin');
  const secure = regDword(k, 'PromptOnSecureDesktop');
  return lua === 1 && secure !== 0 && (admin === 1 || admin === 2);
}

const psQuote = (s: string) => `'${s.replace(/'/g, "''")}'`;

export const windowsConfirmer: Confirmer = {
  async confirm(summary, planHash) {
    if (helloAvailable()) {
      const message = `${summary.split('\n').slice(0, 3).join(' / ')}`.slice(0, 250);
      const r = ps(`${WINRT_PRELUDE}
Await ([Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync(${psQuote(message)})) ([Windows.Security.Credentials.UI.UserConsentVerificationResult])`, 130_000);
      return r.status === 0 && r.stdout === 'Verified';
    }
    if (!uacIsSecureGate()) return false;
    // The elevated process does nothing; approving the secure-desktop UAC prompt is the confirmation.
    // "Show more details" in the prompt displays the plan hash in the command line.
    const r = ps(`try { Start-Process -FilePath "$env:SystemRoot\\System32\\cmd.exe" -ArgumentList '/d /c rem hydra-bane-confirm-${planHash.slice(0, 16)} & exit 0' -Verb RunAs -Wait -WindowStyle Hidden; 'OK' } catch { 'DENIED' }`, 130_000);
    return r.status === 0 && r.stdout === 'OK';
  },
};
