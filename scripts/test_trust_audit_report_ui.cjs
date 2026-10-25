// Exercise the shipped controls without a browser, network, or real clipboard.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

async function test() {
  const views = ['project', 'machine', 'release'].map(name => ({ id: `view-${name}`, hidden: false }));
  const controls = ['project', 'machine', 'release', 'project', 'machine', 'release'].map(name => ({
    dataset: { view: name },
    active: false,
    classList: { toggle(_name, value) { this.value = value; } },
    setAttribute(name, value) { this[name] = value; },
    addEventListener(_event, callback) { this.click = callback; },
  }));
  const details = { open: false };
  const area = {
    value: 'Review only. No upgrades or trust changes.',
    closest: () => details,
    focus() { this.focused = true; },
    select() { this.selected = true; },
  };
  const status = {};
  const copy = {
    dataset: { prompt: 'prompt', status: 'status' },
    addEventListener(_event, callback) { this.click = callback; },
  };
  let copied;
  const context = {
    document: {
      body: { dataset: { initialView: 'project' } },
      querySelectorAll(selector) {
        return { '.view': views, '[data-view]': controls, '.copy': [copy] }[selector];
      },
      getElementById(id) { return { prompt: area, status }[id]; },
    },
    navigator: { clipboard: { async writeText(value) { copied = value; } } },
  };
  const script = fs.readFileSync(path.join(__dirname, '../plugins/guardian-security-scan/data/trust_audit_report.js'), 'utf8');
  vm.runInNewContext(script, context);
  assert.deepEqual(views.map(view => view.hidden), [false, true, true]);
  controls[1].click();
  assert.deepEqual(views.map(view => view.hidden), [true, false, true]);
  assert.equal(controls[4]['aria-pressed'], 'true');
  controls[5].click();
  assert.deepEqual(views.map(view => view.hidden), [true, true, false]);
  await copy.click();
  assert.equal(copied, area.value);
  assert.match(status.textContent, /^Copied/);
  context.navigator.clipboard.writeText = async () => { throw Error('Clipboard unavailable'); };
  await copy.click();
  assert.equal(details.open, true);
  assert.equal(area.selected, true);
  assert.equal(area.focused, true);
  assert.match(status.textContent, /No action has been executed/);
  console.log('Trust report controls passed: navigation, copy and clipboard fallback.');
}
test().catch(error => { console.error(error); process.exitCode = 1; });
