import { newEnforcer } from 'casbin';
import * as path from 'node:path';
import * as fs from 'node:fs';
import * as os from 'node:os';

describe('policy/model.conf — Pitfall 1 canary', () => {
  it('savePolicy() returns true after addPolicy/removePolicy (i.e. [role_definition] present)', async () => {
    // Copy CSV to temp so the real file is not mutated by the round-trip
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'policy-test-'));
    const tmpCsv = path.join(tmp, 'policy.csv');
    fs.copyFileSync(path.join(process.cwd(), 'policy/policy.csv'), tmpCsv);
    const e = await newEnforcer(
      path.join(process.cwd(), 'policy/model.conf'),
      tmpCsv,
    );

    const added = await e.addPolicy('role:canary', '/canary', 'GET');
    expect(added).toBe(true);
    const saved = await e.savePolicy();
    expect(saved).toBe(true); // RESEARCH Pitfall 1: false means no [role_definition] in model.conf

    // Cleanup: removePolicy + savePolicy
    await e.removePolicy('role:canary', '/canary', 'GET');
    await e.savePolicy();
    fs.rmSync(tmp, { recursive: true, force: true });
  });
});
