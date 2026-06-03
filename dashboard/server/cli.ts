#!/usr/bin/env node
import { parseArgs } from 'util';
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

function printHelp(): void {
  process.stderr.write('Usage: dashboard <group> <command> [options]\n\n');
  process.stderr.write('Groups:\n');
  process.stderr.write('  server   Start the Dashboard BFF server\n');
  process.stderr.write('  user     Manage dashboard users\n\n');
  process.stderr.write('Run: dashboard <group> --help\n');
}

function printGroupHelp(group: string): void {
  if (group === 'server') {
    process.stderr.write('Usage: dashboard server <command> [options]\n\n');
    process.stderr.write('Commands:\n');
    process.stderr.write('  start   Start the Dashboard BFF server in the foreground\n\n');
    process.stderr.write('Run: dashboard server <command> --help\n');
  } else if (group === 'user') {
    process.stderr.write('Usage: dashboard user <command> [options]\n\n');
    process.stderr.write('Commands:\n');
    process.stderr.write('  create   Create a new dashboard user and generate an enrollment link\n');
    process.stderr.write('  list     List all dashboard users\n');
    process.stderr.write('  reset    Revoke all passkeys, update user fields, and generate a new enrollment link\n\n');
    process.stderr.write('Run: dashboard user <command> --help\n');
  }
}

const groups: Record<string, Record<string, () => void>> = {
  server: {
    start: () => {
      import('./index').catch((err) => {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : String(err)}\n`);
        process.exitCode = 1;
      });
    },
  },

  user: {
    create: () => {
      const { values } = parseArgs({
        args: process.argv.slice(4),
        options: {
          account: { type: 'string' },
          email: { type: 'string' },
          name: { type: 'string' },
          identity: { type: 'string' },
        },
        strict: false,
      });

      if (!values.account || !values.email || !values.name) {
        process.stderr.write('Usage: dashboard user create --account <shepherdAccountName> --email <email> --name <displayName> [--identity <vigil://uri>]\n');
        process.exit(1);
      }

      const config = loadConfig();
      initUsersStore(config.auth.usersPath);
      const { users } = loadUsers();

      if (findUserByShepherdAccount(users, values.account as string)) {
        process.stderr.write(`Error: A user linked to shepherd account '${values.account}' already exists.\n`);
        process.exit(1);
      }

      const { user, rawToken } = createUser(
        values.account as string,
        values.name as string,
        values.email as string,
        config.auth.enrollmentTokenTTLHours,
        values.identity as string | undefined
      );
      users.push(user);
      saveUsers({ users });

      const enrollUrl = `${config.auth.origin}/enroll/${rawToken}`;
      process.stdout.write(`Created user: ${user.displayName} (${user.shepherdAccount})\n`);
      if (user.identityUri) {
        process.stdout.write(`Identity URI: ${user.identityUri}\n`);
      }
      process.stdout.write(`\nEnrollment URL (expires in ${config.auth.enrollmentTokenTTLHours}h):\n${enrollUrl}\n`);
      process.stdout.write('\nSend this URL to the user. They will need their Vigil cert + key to complete enrollment.\n');
    },

    list: () => {
      const config = loadConfig();
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
    },

    reset: () => {
      const { values } = parseArgs({
        args: process.argv.slice(4),
        options: {
          account: { type: 'string' },
          email: { type: 'string' },
          name: { type: 'string' },
          identity: { type: 'string' },
        },
        strict: false,
      });

      if (!values.account) {
        process.stderr.write('Usage: dashboard user reset --account <shepherdAccountName> [--email <email>] [--name <displayName>] [--identity <vigil://uri>]\n');
        process.exit(1);
      }

      const config = loadConfig();
      initUsersStore(config.auth.usersPath);
      const { users } = loadUsers();
      const idx = users.findIndex((u) => u.shepherdAccount === values.account);

      if (idx === -1) {
        process.stderr.write(`Error: No user found with shepherd account '${values.account}'.\n`);
        process.exit(1);
      }

      const fieldUpdates: UserFieldUpdates = {};
      if (values.name) fieldUpdates.displayName = values.name as string;
      if (values.email) fieldUpdates.email = values.email as string;
      if (values.identity) fieldUpdates.identityUri = values.identity as string;

      const { user: updated, rawToken } = regenerateInvite(users[idx], config.auth.enrollmentTokenTTLHours, fieldUpdates);
      users[idx] = updated;
      saveUsers({ users });

      const enrollUrl = `${config.auth.origin}/enroll/${rawToken}`;
      process.stdout.write(`Reset user: ${updated.displayName} (${updated.shepherdAccount}) — all passkeys revoked.\n`);
      if (updated.identityUri) {
        process.stdout.write(`Identity URI: ${updated.identityUri}\n`);
      }
      process.stdout.write(`\nNew enrollment URL (expires in ${config.auth.enrollmentTokenTTLHours}h):\n${enrollUrl}\n`);
    },
  },
};

const [group, subcommand] = process.argv.slice(2);

if (!group || group === '--help' || group === '-h') {
  printHelp();
  process.exit(group ? 0 : 1);
}

const groupCmds = groups[group];
if (!groupCmds) {
  process.stderr.write(`Unknown group: ${group}\n\n`);
  printHelp();
  process.exit(1);
}

if (!subcommand || subcommand === '--help' || subcommand === '-h') {
  printGroupHelp(group);
  process.exit(subcommand ? 0 : 1);
}

const cmd = groupCmds[subcommand];
if (!cmd) {
  process.stderr.write(`Unknown command: ${group} ${subcommand}\n\n`);
  printGroupHelp(group);
  process.exit(1);
}

cmd();
