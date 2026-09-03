import dotenv from 'dotenv';
import {
  ScenarioType,
  SCENARIO_DEFINITIONS,
  loginAndGetToken,
  runSimulation,
  normalizeApiUrl,
  EventDispatchResult,
} from '../src/simulator/telemetrySimulator';

dotenv.config();

const printHelp = () => {
  console.log(`
================================================================================
  AI-SOC LOCAL TELEMETRY SIMULATOR
================================================================================

Usage:
  npm run simulate [-- [options] [scenario]]
  npx tsx scripts/simulate-telemetry.ts [options] [scenario]

Scenarios:
  ALL                  (default) Run all scenarios sequentially in one-shot demo mode
  NORMAL_ACTIVITY      Generate benign login and internal network activity (0 alerts)
  BRUTE_FORCE          Generate 5 rapid LOGIN_FAILED events (triggers threshold rule)
  PORT_SCAN            Generate a network reconnaissance PORT_SCAN event (HIGH alert)
  CRITICAL_EVENT       Generate a CRITICAL malware event (CRITICAL alert)
  UNAUTHORIZED_ACCESS  Generate an unauthorized resource access event

Options:
  --scenario=<name>    Select a specific scenario (case-insensitive)
  --api-url=<url>      Base API URL (default: http://localhost:4000 or process.env.API_URL)
  --delay=<ms>         Delay in ms between events (default: 150)
  --help, -h           Show this help message

Authentication (set via environment or .env):
  AUTH_TOKEN=<jwt>     Provide a pre-generated JWT Bearer token
  OR
  ADMIN_EMAIL=<email>  Email of an existing ADMIN or SOC_ANALYST account
  ADMIN_PASSWORD=<pw>  Password for the account (used to obtain token automatically)
================================================================================
`);
};

const parseCliArgs = () => {
  const args = process.argv.slice(2);
  let scenario: ScenarioType = 'ALL';
  let apiUrl = process.env.API_URL || process.env.AI_SOC_API_URL || 'http://localhost:4000';
  let delayMs = 150;

  for (const arg of args) {
    if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    } else if (arg.startsWith('--scenario=')) {
      const val = arg.split('=')[1].trim().toUpperCase();
      scenario = val as ScenarioType;
    } else if (arg.startsWith('--api-url=')) {
      apiUrl = arg.split('=')[1].trim();
    } else if (arg.startsWith('--delay=')) {
      delayMs = parseInt(arg.split('=')[1].trim(), 10) || 150;
    } else if (!arg.startsWith('--')) {
      const upper = arg.trim().toUpperCase();
      if (upper in SCENARIO_DEFINITIONS || upper === 'ALL') {
        scenario = upper as ScenarioType;
      }
    }
  }

  return { scenario, apiUrl, delayMs };
};

const resolveAuthToken = async (apiUrl: string): Promise<string> => {
  // 1. Direct token provided in environment
  const directToken = process.env.AUTH_TOKEN || process.env.JWT_TOKEN || process.env.API_TOKEN;
  if (directToken && directToken.trim()) {
    return directToken.trim();
  }

  // 2. Credentials provided in environment to perform automatic login
  const email = process.env.ADMIN_EMAIL || process.env.SIM_EMAIL || process.env.ANALYST_EMAIL;
  const password = process.env.ADMIN_PASSWORD || process.env.SIM_PASSWORD || process.env.ANALYST_PASSWORD;

  if (email && password) {
    console.log(`[Simulator] Authenticating with AI-SOC as "${email.toLowerCase()}"...`);
    const token = await loginAndGetToken(apiUrl, email, password);
    console.log('[Simulator] Authentication successful.');
    return token;
  }

  throw new Error(
    'No authentication token or credentials provided.\n' +
    'Please set AUTH_TOKEN=<jwt> or ADMIN_EMAIL=<email> & ADMIN_PASSWORD=<password> in your .env or environment.'
  );
};

const main = async () => {
  const { scenario, apiUrl, delayMs } = parseCliArgs();
  const normalizedUrl = normalizeApiUrl(apiUrl);

  console.log('================================================================================');
  console.log('  AI-SOC LOCAL TELEMETRY SIMULATOR');
  console.log('================================================================================');
  console.log(`Target API : ${normalizedUrl}/api/events/ingest`);
  console.log(`Scenario   : ${scenario}`);
  console.log('--------------------------------------------------------------------------------');

  const token = await resolveAuthToken(normalizedUrl);

  console.log('--------------------------------------------------------------------------------');
  console.log('[Simulator] Starting simulation dispatch...');
  console.log('--------------------------------------------------------------------------------');

  const summary = await runSimulation({
    apiUrl: normalizedUrl,
    token,
    scenario,
    delayMs,
    onEventDispatched: (result: EventDispatchResult, index: number, total: number) => {
      const prefix = `[${index}/${total}] Scenario: ${result.scenario.padEnd(19)} | Event: ${result.eventType.padEnd(20)} | Source: ${result.source.padEnd(18)}`;
      if (result.success) {
        const alertsText = result.alertsGenerated > 0
          ? `Alerts Generated: ${result.alertsGenerated} [${result.alertTitles.join(', ')}]`
          : 'Alerts Generated: 0';
        console.log(`${prefix} | Result: SUCCESS (ID: ${result.eventId}) | ${alertsText}`);
      } else {
        console.error(`${prefix} | Result: FAILED (Status: ${result.statusCode}) | Error: ${result.error}`);
      }
    },
  });

  console.log('--------------------------------------------------------------------------------');
  console.log('SIMULATION SUMMARY');
  console.log('--------------------------------------------------------------------------------');
  console.log(`Total Events Simulated   : ${summary.totalEvents}`);
  console.log(`Successful Ingestions    : ${summary.successfulEvents}`);
  console.log(`Failed Ingestions        : ${summary.failedEvents}`);
  console.log(`Total Alerts Triggered   : ${summary.totalAlerts}`);
  console.log('================================================================================');

  if (summary.failedEvents > 0) {
    process.exitCode = 1;
  }
};

main().catch((error) => {
  console.error('\n[Simulator Error]:', error instanceof Error ? error.message : error);
  process.exitCode = 1;
});

