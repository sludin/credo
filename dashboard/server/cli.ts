#!/usr/bin/env node
import { Command } from 'commander';
import { X509Certificate, createSign } from 'crypto';
import fs from 'fs';
import { loadConfig } from './config';
import {
  initUsersStore,
  loadUsers,
  saveUsers,
  findUserByShepherdAccount,
  createUser,
  regenerateInvite,
  type UserFieldUpdates,
} from './auth/users';

function printTable(rows: Array<Record<string, string>>): void {
  if (rows.length === 0) { process.stdout.write('(no users)\n'); return; }
  const cols = Object.keys(rows[0]);
  const widths = cols.map((c) => Math.max(c.length, ...rows.map((r) => (r[c] ?? '').length)));
  const header = cols.map((c, i) => c.padEnd(widths[i])).join('  ');
  const divider = widths.map((w) => '-'.repeat(w)).join('  ');
  process.stdout.write(header + '\n' + divider + '\n');
  for (const row of rows) {
    process.stdout.write(cols.map((c, i) => (row[c] ?? '').padEnd(widths[i])).join('  ') + '\n');
  }
}

const program = new Command();

program
  .name('dashboard')
  .description('Dashboard BFF management CLI')
  .version('0.1.0');

// ---------------------------------------------------------------------------
// server
// ---------------------------------------------------------------------------

const server = program.command('server').description('Server commands');

server
  .command('start')
  .description('Start the Dashboard BFF server in the foreground')
  .action(() => {
    import('./index').catch((err) => {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 1;
    });
  });

// ---------------------------------------------------------------------------
// user
// ---------------------------------------------------------------------------

const user = program.command('user').description('Manage dashboard users');

user
  .command('create')
  .description('Create a new dashboard user and generate an enrollment link')
  .requiredOption('--account <name>', 'Shepherd account name')
  .requiredOption('--email <email>', 'User email address')
  .requiredOption('--name <display>', 'User display name')
  .requiredOption('--identity <uri>', 'Vigil identity URI (vigil://...)')
  .action((opts: { account: string; email: string; name: string; identity: string }) => {
    const config = loadConfig({ skipTlsCheck: true });
    initUsersStore(config.auth.usersPath);
    const { users } = loadUsers();

    if (findUserByShepherdAccount(users, opts.account)) {
      process.stderr.write(`Error: A user linked to shepherd account '${opts.account}' already exists.\n`);
      process.exit(1);
    }

    const { user: newUser, rawToken } = createUser(
      opts.account,
      opts.name,
      opts.email,
      config.auth.enrollmentTokenTTLHours,
      opts.identity,
    );
    users.push(newUser);
    saveUsers({ users });

    const enrollUrl = `${config.auth.origin}/enroll/${rawToken}`;
    process.stdout.write(`Created user: ${newUser.displayName} (${newUser.shepherdAccount})\n`);
    process.stdout.write(`Identity URI: ${newUser.identityUri}\n`);
    process.stdout.write(`\nEnrollment URL (expires in ${config.auth.enrollmentTokenTTLHours}h):\n${enrollUrl}\n`);
    process.stdout.write('\nSend this URL to the user. They will need their Vigil cert + key to complete enrollment.\n');
  });

user
  .command('list')
  .description('List all dashboard users')
  .action(() => {
    const config = loadConfig({ skipTlsCheck: true });
    initUsersStore(config.auth.usersPath);
    const { users } = loadUsers();

    printTable(users.map((u) => ({
      id: u.id,
      shepherdAccount: u.shepherdAccount,
      displayName: u.displayName,
      email: u.email,
      active: String(u.active),
      passkeys: String(u.passkeys.length),
      enrolled: u.pendingInvite === null ? 'yes' : 'pending',
    })));
  });

user
  .command('reset')
  .description('Revoke all passkeys, update user fields, and generate a new enrollment link')
  .requiredOption('--account <name>', 'Shepherd account name')
  .option('--email <email>', 'Update email address')
  .option('--name <display>', 'Update display name')
  .option('--identity <uri>', 'Update Vigil identity URI')
  .action((opts: { account: string; email?: string; name?: string; identity?: string }) => {
    const config = loadConfig({ skipTlsCheck: true });
    initUsersStore(config.auth.usersPath);
    const { users } = loadUsers();
    const idx = users.findIndex((u) => u.shepherdAccount === opts.account);

    if (idx === -1) {
      process.stderr.write(`Error: No user found with shepherd account '${opts.account}'.\n`);
      process.exit(1);
    }

    const fieldUpdates: UserFieldUpdates = {};
    if (opts.name) fieldUpdates.displayName = opts.name;
    if (opts.email) fieldUpdates.email = opts.email;
    if (opts.identity) fieldUpdates.identityUri = opts.identity;

    const { user: updated, rawToken } = regenerateInvite(users[idx], config.auth.enrollmentTokenTTLHours, fieldUpdates);
    users[idx] = updated;
    saveUsers({ users });

    const enrollUrl = `${config.auth.origin}/enroll/${rawToken}`;
    process.stdout.write(`Reset user: ${updated.displayName} (${updated.shepherdAccount}) — all passkeys revoked.\n`);
    if (updated.identityUri) {
      process.stdout.write(`Identity URI: ${updated.identityUri}\n`);
    }
    process.stdout.write(`\nNew enrollment URL (expires in ${config.auth.enrollmentTokenTTLHours}h):\n${enrollUrl}\n`);
  });

// ---------------------------------------------------------------------------
// enroll
// ---------------------------------------------------------------------------

program
  .command('enroll')
  .description('Generate a PoP token to paste into the browser enrollment page')
  .requiredOption('--cert <path>', 'Path to Vigil client certificate PEM')
  .requiredOption('--key <path>', 'Path to Vigil client private key PEM')
  .requiredOption('--challenge <token>', 'Enrollment token from the /enroll/<token> URL')
  .action((opts: { cert: string; key: string; challenge: string }) => {
    let certPem: string;
    let keyPem: string;
    try {
      certPem = fs.readFileSync(opts.cert, 'utf8');
    } catch (err) {
      process.stderr.write(`Error reading cert: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(1);
    }
    try {
      keyPem = fs.readFileSync(opts.key, 'utf8');
    } catch (err) {
      process.stderr.write(`Error reading key: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(1);
    }

    let identityUri: string;
    try {
      const x509 = new X509Certificate(certPem);
      const san = x509.subjectAltName ?? '';
      const uriEntry = san
        .split(',')
        .map((s) => s.trim())
        .find((s) => s.startsWith('URI:vigil://'));
      if (!uriEntry) {
        process.stderr.write('Error: Certificate has no vigil:// URI in Subject Alternative Names.\n');
        process.exit(1);
      }
      identityUri = uriEntry.slice(4).trim();
    } catch (err) {
      process.stderr.write(`Error parsing certificate: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(1);
    }

    const issuedAt = new Date().toISOString();
    const message = Buffer.concat([
      Buffer.from(opts.challenge, 'hex'),
      Buffer.from(identityUri),
      Buffer.from(issuedAt),
    ]);

    let signature: string;
    try {
      const sign = createSign('SHA256');
      sign.update(message);
      signature = sign.sign(keyPem, 'base64url');
    } catch (err) {
      process.stderr.write(`Error signing: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(1);
    }

    const pop = { cert: certPem, signature, challenge: opts.challenge, identityUri, issuedAt };
    process.stdout.write(JSON.stringify(pop, null, 2) + '\n');
  });

program.parse();
