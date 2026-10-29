// Portable fixture replay: copied beside the installed consumer and executed
// unchanged in its realm without Node globals or built-ins.
const sort = v => Array.isArray(v) ? v.map(sort) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k => [k, sort(v[k])])) : v;
const bytes = v => new TextEncoder().encode(JSON.stringify(sort(v)));
/** A fixture input with each candidate's report document read through the public reader. */
export const summaryFixtureInput = async (api, entry) => {
  const input = JSON.parse(JSON.stringify(entry.input));
  input.records = await Promise.all(input.records.map(async ({ report, ...candidate }) => ({ ...candidate, artifact: await api.readReport(bytes(report)) })));
  return input;
};
export async function replayItemSummaries(api, fixtures) {
  const entries = [...fixtures.cases.filter(c => c.input), ...fixtures.variants];
  for (const entry of entries) {
    const result = await api.summariseItem(await summaryFixtureInput(api, entry));
    if (result.status !== 'summarised' || JSON.stringify(sort(result.summary)) !== JSON.stringify(sort(entry.value)))
      throw new Error(`Item summary ${entry.name}: ${JSON.stringify(result)}`);
    const picked = result.picked && { index: result.picked.index, why: result.picked.why };
    if (entry.picked && JSON.stringify(picked) !== JSON.stringify(entry.picked))
      throw new Error(`Item summary ${entry.name} picked ${JSON.stringify(result.picked)}`);
    if (entry.row <= 3 && result.picked !== null) throw new Error(`Item summary ${entry.name} must pick no record`);
  }
  return { rows: fixtures.cases.filter(c => c.input).map(c => c.row), variants: fixtures.variants.length };
}
